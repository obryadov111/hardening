"""Этап 2: несколько паков на один актив, паки docker / astra-linux / cisco-ios.

Cisco проверен на образцах вывода (устройства нет — пак maturity=draft); Astra — только обнаружение;
Docker подтверждён и на реальном docker этого хоста (см. отчёт этапа), здесь — на смоделированных ответах."""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import text

from app.api.deps import get_pack_registry
from app.services.packs.evaluate import evaluate_pack
from app.services.packs.manifest import build_manifest

REPO = Path(__file__).resolve().parents[3]
if not (REPO / "agent" / "probes.py").exists():
    pytest.skip("каталог agent/ недоступен (тесты запущены вне репозитория)", allow_module_level=True)
sys.path.insert(0, str(REPO / "agent"))

import probes  # noqa: E402

from tests import test_ubuntu_pack_regression as regression  # noqa: E402

REGISTRY = get_pack_registry()
PACKS = {p.pack: p for p in REGISTRY.latest()}
MANIFESTS = {name: build_manifest(pack) for name, pack in PACKS.items()}


def statuses(pack_name, transport):
    raw = probes.run_manifest(transport, MANIFESTS[pack_name])
    return {r.check_id: r.status for r in evaluate_pack(PACKS[pack_name], {k: SimpleNamespace(**v) for k, v in raw.items()})}


# ============================== Cisco IOS ==============================

BANNER_IOS = "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)\n"
BANNER_XE = "Cisco IOS XE Software, Version 16.09.04\nCisco IOS Software [Fuji], Catalyst L3 Switch Software\n"

CISCO_HARDENED = """\
Building configuration...

Current configuration : 2345 bytes
!
version 15.2
service password-encryption
!
hostname sw-core-01
!
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
!
aaa new-model
!
ip ssh version 2
no ip http server
no ip http secure-server
!
snmp-server community K7x9Qm2 RO 10
!
ntp server 10.0.0.1
!
line con 0
 logging synchronous
line vty 0 4
 access-class 10 in
 transport input ssh
line vty 5 15
 access-class 10 in
 transport input ssh
!
end
"""

CISCO_WEAK = """\
Building configuration...
!
version 15.2
no service password-encryption
!
hostname sw-edge-07
!
enable password 7 0822455D0A16
!
ip http server
!
snmp-server community public RO
!
line con 0
line vty 0 4
 transport input all
line vty 5 15
 transport input telnet ssh
!
end
"""


class Router:
    """Ответы устройства по командам; учитывает, какие команды запрашивались."""

    def __init__(self, outputs):
        self.outputs, self.commands = outputs, []

    def __call__(self, argv, **kwargs):
        command = argv[-1]
        self.commands.append(command)
        out = self.outputs.get(command, "% Invalid input detected at '^' marker.\n")
        return SimpleNamespace(stdout=out, stderr="", returncode=0)


def cisco(config, banner=BANNER_IOS):
    router = Router({"show version": banner, "show running-config": config})
    return probes.SshTransport("10.0.0.1", "audit", runner=router), router


@pytest.mark.parametrize("banner", [BANNER_IOS, BANNER_XE], ids=["IOS", "IOS XE"])
def test_cisco_pack_is_detected_on_ios_and_ios_xe(banner):
    transport, _ = cisco(CISCO_HARDENED, banner)
    assert probes.select_manifests(transport, [MANIFESTS["cisco-ios"]]) == [MANIFESTS["cisco-ios"]]


@pytest.mark.parametrize("banner", ["JUNOS 20.4R3", "Linux router 5.15", "MikroTik RouterOS 7.11", ""], ids=["junos", "linux", "mikrotik", "empty"])
def test_cisco_pack_is_not_detected_on_other_platforms(banner):
    transport, _ = cisco(CISCO_HARDENED, banner)
    assert probes.select_manifests(transport, [MANIFESTS["cisco-ios"]]) == []


def test_cisco_hardened_config_passes_everything():
    transport, _ = cisco(CISCO_HARDENED)
    result = statuses("cisco-ios", transport)
    assert len(result) == 11 and set(result.values()) == {"pass"}, {k: v for k, v in result.items() if v != "pass"}


def test_cisco_weak_config_each_violation_is_caught_by_exactly_one_check():
    transport, _ = cisco(CISCO_WEAK)
    result = statuses("cisco-ios", transport)
    # 1.1.0: пары проверок разведены. Обратимый `enable password` ловит enable_password_absent
    # (enable_credential_set проходит: пароль задан), `transport input all` — vty_telnet_disabled
    # (vty_transport_explicit проходит: транспорт задан явно). Остальное — провал.
    both_ok = {"cisco_ios.enable_credential_set", "cisco_ios.vty_transport_explicit"}
    assert {k for k, v in result.items() if v == "pass"} == both_ok
    assert {k for k, v in result.items() if v != "pass"} == set(result) - both_ok
    assert set(result.values()) == {"pass", "fail"}


def test_cisco_vty_telnet_in_any_block_is_caught():
    config = CISCO_HARDENED.replace("line vty 5 15\n access-class 10 in\n transport input ssh", "line vty 5 15\n access-class 10 in\n transport input telnet")
    result = statuses("cisco-ios", cisco(config)[0])
    assert result["cisco_ios.vty_telnet_disabled"] == "fail"  # первый блок в порядке, второй разрешает telnet
    assert result["cisco_ios.vty_transport_explicit"] == "pass"  # транспорт задан явно в обоих блоках


def test_cisco_probe_reads_only_show_commands():
    transport, router = cisco(CISCO_HARDENED)
    statuses("cisco-ios", transport)
    assert set(router.commands) == {"show running-config"}  # детект (show version) в statuses не входит
    assert all(probes.is_readonly_cli(c) for c in router.commands)


@pytest.mark.parametrize("denied", [
    "% Invalid input detected at '^' marker.\n",
    "% Authorization failed.\n",
    "\n\n% Incomplete command.\n",
    "",  # пустой ответ
    "Building configuration...\n\nCurrent configuration : 12 bytes\n",  # обрыв: нет завершающего end
])
def test_insufficient_privilege_never_produces_false_passes(denied):
    """Без прав нет конфигурации: «параметра нет» (absent) на пустом выводе обязано быть error, не pass."""
    result = statuses("cisco-ios", cisco(denied)[0])
    assert set(result.values()) == {"error"}, {k: v for k, v in result.items() if v != "error"}


def test_cisco_evidence_never_contains_secrets():
    transport, _ = cisco(CISCO_WEAK)
    raw = probes.run_manifest(transport, MANIFESTS["cisco-ios"])
    evidences = [v["evidence"] for v in raw.values() if v["evidence"]]
    assert "enable password ***" in evidences and "snmp-server community ***" in evidences
    assert not any(secret in e for e in evidences for secret in ("0822455D0A16", "public"))


def test_cisco_pack_is_a_draft_and_says_so():
    pack = PACKS["cisco-ios"]
    assert pack.maturity == "draft" and pack.verified_on == [] and pack.transport == "ssh"


# ============================== Astra Linux ==============================

@pytest.mark.parametrize("os_release", [
    'PRETTY_NAME="Astra Linux 1.7.5 (Smolensk)"\nNAME="Astra Linux"\nID=astra\n',
    'NAME="Astra Linux"\nVERSION_ID="1.8"\n',
    "ID=astra\n",
    'PRETTY_NAME="Astra Linux Special Edition"\n',
], ids=["полный", "только NAME", "только ID", "только PRETTY_NAME"])
def test_astra_is_detected_by_any_astra_marker_in_os_release(os_release):
    host = regression.make_host({"/etc/os-release": os_release})
    assert probes.matches_detect(host, MANIFESTS["astra-linux"]["detect"])


@pytest.mark.parametrize("os_release", ['ID=ubuntu\nNAME="Ubuntu"\n', "ID=debian\n", 'NAME="Fedora Linux"\n', "ID=alt\nNAME=\"ALT Linux\"\n"])
def test_astra_is_not_detected_on_other_systems(os_release):
    host = regression.make_host({"/etc/os-release": os_release})
    assert not probes.matches_detect(host, MANIFESTS["astra-linux"]["detect"])


def test_astra_host_gets_astra_pack_and_not_the_ubuntu_pack():
    host = regression.make_host({"/etc/os-release": 'ID=astra\nNAME="Astra Linux"\n'})
    matched = [m["pack"] for m in probes.select_manifests(host, [MANIFESTS[n] for n in ("ubuntu-server", "astra-linux")])]
    assert matched == ["astra-linux"]


def test_astra_pack_is_inventory_only_without_any_checks():
    pack = PACKS["astra-linux"]
    assert pack.maturity == "inventory" and pack.checks == []


# ============================== Docker ==============================

class Host(regression.FakeHost):
    """Смоделированный хост, умеющий stat (для сокета docker)."""

    def stat_file(self, path):
        if path not in self.files:
            raise probes.ProbeError(f"нет {path}")
        return SimpleNamespace(st_mode=0o140660, st_uid=0, st_gid=999)


# Безопасные значения по умолчанию для полей inspect, добавленных в 1.1.0: контейнер без лишних
# монтирований, без явного root, с лимитами CPU/памяти, не в hostNetwork/hostPID — чтобы старые
# сценарии (заданные только флагом privileged) не превращались в fail/error по новым проверкам.
DOCKER_SAFE_DEFAULTS = {
    "HostConfig.Privileged": "false",
    "HostConfig.Binds": "[]",
    "Config.User": "",
    "HostConfig.Memory": "104857600",
    "HostConfig.NanoCpus": "500000000",
    "HostConfig.NetworkMode": "bridge",
    "HostConfig.PidMode": "",
}
# Статусы шести новых проверок 1.1.0 при безопасных значениях по умолчанию — используется там, где
# тест варьирует только один параметр (privileged) и не хочет переписывать весь ожидаемый словарь.
DOCKER_SAFE_STATUSES = {
    "docker.no_sensitive_host_mounts": "pass",
    "docker.no_root_user_explicit": "pass",
    "docker.memory_limit_set": "pass",
    "docker.cpu_limit_set": "pass",
    "docker.no_host_network": "pass",
    "docker.no_host_pid": "pass",
}


def docker_host(containers=None, ps_code=0, with_socket=True):
    """containers: {id: "true"/"false"} — только флаг privileged (остальные поля inspect получают
    DOCKER_SAFE_DEFAULTS), либо {id: {"HostConfig.Binds": ..., ...}} — точечная настройка любых
    полей inspect поверх умолчаний."""
    commands = dict(regression.HARDENED_COMMANDS)
    commands["docker ps -q"] = ("".join(f"{cid}\n" for cid in (containers or {})), "permission denied" if ps_code else "", ps_code)
    for cid, cfg in (containers or {}).items():
        overrides = {"HostConfig.Privileged": cfg} if isinstance(cfg, str) else cfg
        fields = {**DOCKER_SAFE_DEFAULTS, **overrides}
        for field, value in fields.items():
            commands[f"docker inspect --format {{{{.{field}}}}} {cid}"] = (f"{value}\n", "", 0)
    files = dict(regression.HARDENED_FILES)
    if with_socket:
        files["/var/run/docker.sock"] = ""
    return Host(files, commands)


def test_docker_pack_detected_only_when_socket_exists():
    assert probes.matches_detect(docker_host(), MANIFESTS["docker"]["detect"])
    assert not probes.matches_detect(docker_host(with_socket=False), MANIFESTS["docker"]["detect"])


@pytest.mark.parametrize("containers, expected", [
    ({}, "pass"),  # контейнеров нет
    ({"aaa111bbb222": "false", "ccc333ddd444": "false"}, "pass"),
    ({"aaa111bbb222": "false", "ccc333ddd444": "true"}, "fail"),
])
def test_docker_privileged_check(containers, expected):
    assert statuses("docker", docker_host(containers)) == {"docker.no_privileged_containers": expected, **DOCKER_SAFE_STATUSES}


def test_docker_unavailable_is_error_not_a_pass():
    # старый агент: docker отказал -> нет факта -> error; пак сохраняет это (а не «привилегированных нет»)
    # docker ps -q отказывает одинаково для всех семи проверок пака (каждая сама вызывает list_cmd).
    all_error = {c.id: "error" for c in PACKS["docker"].checks}
    assert statuses("docker", docker_host({"aaa111bbb222": "true"}, ps_code=1)) == all_error


# ---------- новые проверки 1.1.0 (методика ФСТЭК, раздел СКО) ----------

@pytest.mark.parametrize("binds, expected", [
    ("[]", "pass"),
    ("[myvolume:/data:rw]", "pass"),  # именованный том, не путь хоста — не считается чувствительным
    ("[/etc:/etc:ro]", "fail"),
    ("[/var/run/docker.sock:/var/run/docker.sock]", "fail"),
    ("[/home/user/app:/app:rw /etc:/etc/app:ro]", "fail"),  # чувствительный путь среди прочих монтирований
])
def test_docker_no_sensitive_host_mounts(binds, expected):
    host = docker_host({"aaa111bbb222": {"HostConfig.Binds": binds}})
    assert statuses("docker", host)["docker.no_sensitive_host_mounts"] == expected


@pytest.mark.parametrize("user, expected", [
    ("", "pass"),  # не задано явно — не нарушение (эффективный пользователь образа агенту неизвестен)
    ("appuser", "pass"),
    ("1000", "pass"),
    ("root", "fail"),
    ("0", "fail"),
])
def test_docker_no_root_user_explicit(user, expected):
    host = docker_host({"aaa111bbb222": {"Config.User": user}})
    assert statuses("docker", host)["docker.no_root_user_explicit"] == expected


@pytest.mark.parametrize("memory, expected", [("0", "fail"), ("536870912", "pass")])
def test_docker_memory_limit_set(memory, expected):
    host = docker_host({"aaa111bbb222": {"HostConfig.Memory": memory}})
    assert statuses("docker", host)["docker.memory_limit_set"] == expected


@pytest.mark.parametrize("nanocpus, expected", [("0", "fail"), ("1000000000", "pass")])
def test_docker_cpu_limit_set(nanocpus, expected):
    host = docker_host({"aaa111bbb222": {"HostConfig.NanoCpus": nanocpus}})
    assert statuses("docker", host)["docker.cpu_limit_set"] == expected


@pytest.mark.parametrize("network_mode, expected", [("host", "fail"), ("bridge", "pass"), ("my-custom-net", "pass")])
def test_docker_no_host_network(network_mode, expected):
    host = docker_host({"aaa111bbb222": {"HostConfig.NetworkMode": network_mode}})
    assert statuses("docker", host)["docker.no_host_network"] == expected


@pytest.mark.parametrize("pid_mode, expected", [("host", "fail"), ("", "pass")])
def test_docker_no_host_pid(pid_mode, expected):
    host = docker_host({"aaa111bbb222": {"HostConfig.PidMode": pid_mode}})
    assert statuses("docker", host)["docker.no_host_pid"] == expected


def test_docker_pack_matches_legacy_rule_on_the_same_host(monkeypatch):
    """Регрессия для 14-го правила: старый агент и пак дают один статус на одном и том же хосте."""
    for containers in ({}, {"aaa111bbb222": "false"}, {"aaa111bbb222": "true"}):
        host = docker_host(containers)
        monkeypatch.setattr(regression.collector, "read_file", host.legacy_read_file)
        monkeypatch.setattr(regression.collector, "run", host.legacy_run)
        facts = regression.collector.collect_docker_facts()
        legacy = "pass" if facts.get("no_privileged_containers") == "true" else "fail"
        assert statuses("docker", host)["docker.no_privileged_containers"] == legacy


# ============================== PostgreSQL ==============================
# maturity=draft: проверки написаны по документации (методика ФСТЭК, раздел СУБД) и сверены
# регэкспами с реальным PostgreSQL (контейнер diploma_db этого хоста, только чтение), но не
# прогонялись живым агентом на реальном Ubuntu-хосте с postgresql-16 по стандартным путям пакета.

class StatHost(regression.FakeHost):
    """Смоделированный хост с управляемыми правами файлов (для file_stat), без привязки к
    конкретному типу файла (в отличие от docker-специфичного Host выше)."""

    def __init__(self, files, commands=None, modes=None):
        super().__init__(files, commands or {})
        self.modes = modes or {}

    def stat_file(self, path):
        if path not in self.files and path not in self.modes:
            raise probes.ProbeError(f"нет {path}")
        return SimpleNamespace(st_mode=self.modes.get(path, 0o100644), st_uid=0, st_gid=0)


PG_CONF_PATH = "/etc/postgresql/16/main/postgresql.conf"
PG_HBA_PATH = "/etc/postgresql/16/main/pg_hba.conf"
PG_LOG_PATH = "/var/log/postgresql/postgresql-16-main.log"
PG_DATA_PATH = "/var/lib/postgresql/16/main"

PG_HARDENED_CONF = "listen_addresses = 'localhost'\nssl = on\nssl_min_protocol_version = 'TLSv1.2'\n"
PG_HARDENED_HBA = "local   all all                trust\nhost    all all 127.0.0.1/32 scram-sha-256\nhost    all all ::1/128     scram-sha-256\n"
# Реальные строки, снятые с контейнера diploma_db этого хоста (2026-09-24, только чтение):
PG_WEAK_HBA = (
    "local   all             all                                     trust\n"
    "host    all             all             127.0.0.1/32            trust\n"
    "host    all             all             ::1/128                 trust\n"
    "host all all all scram-sha-256\n"
)


def postgres_host(conf=PG_HARDENED_CONF, hba=PG_HARDENED_HBA, log_mode=0o100640, data_mode=0o40700, with_conf=True):
    files = {PG_HBA_PATH: hba}
    if with_conf:
        files[PG_CONF_PATH] = conf
    modes = {PG_LOG_PATH: log_mode, PG_DATA_PATH: data_mode}
    if PG_LOG_PATH not in files:
        files[PG_LOG_PATH] = ""  # содержимое не читается (только stat), но stat_file требует наличия пути
    if PG_DATA_PATH not in files:
        files[PG_DATA_PATH] = ""
    return StatHost(files, modes=modes)


def test_postgresql_pack_detected_only_when_conf_exists():
    assert probes.matches_detect(postgres_host(), MANIFESTS["postgresql"]["detect"])
    assert not probes.matches_detect(postgres_host(with_conf=False), MANIFESTS["postgresql"]["detect"])


def test_postgresql_hardened_host_passes_everything():
    result = statuses("postgresql", postgres_host())
    assert len(result) == 6 and set(result.values()) == {"pass"}, {k: v for k, v in result.items() if v != "pass"}


def test_postgresql_real_weak_config_from_this_hosts_container_fails_as_expected():
    """Реальный pg_hba.conf/postgresql.conf контейнера diploma_db (снято 2026-09-24, только чтение) —
    честная проверка, что паттерны пака действительно ловят то, что реально есть на этом хосте."""
    weak_conf = "listen_addresses = '*'\n"  # ssl/ssl_min_protocol_version не заданы — реальное состояние
    host = postgres_host(conf=weak_conf, hba=PG_WEAK_HBA, log_mode=0o100640, data_mode=0o40700)
    result = statuses("postgresql", host)
    assert result["postgres.pg_hba_no_unrestricted_host"] == "fail"
    assert result["postgres.listen_addresses_not_all_interfaces"] == "fail"
    assert result["postgres.ssl_enabled"] == "fail"  # default "off" — ssl не задан вовсе
    assert result["postgres.ssl_min_protocol_version_modern"] == "pass"  # default TLSv1.2 — не задан, но безопасен
    assert result["postgres.log_directory_not_world_readable"] == "pass"
    assert result["postgres.data_directory_permissions"] == "pass"


@pytest.mark.parametrize("hba, expected", [
    (PG_HARDENED_HBA, "pass"),
    ("host all all 0.0.0.0/0 scram-sha-256\n", "fail"),
    ("host all all ::/0 scram-sha-256\n", "fail"),
    ("host all all all scram-sha-256\n", "fail"),
])
def test_postgresql_pg_hba_unrestricted_host(hba, expected):
    assert statuses("postgresql", postgres_host(hba=hba))["postgres.pg_hba_no_unrestricted_host"] == expected


@pytest.mark.parametrize("listen, expected", [("'localhost'", "pass"), ("'*'", "fail"), ("'0.0.0.0'", "fail")])
def test_postgresql_listen_addresses(listen, expected):
    conf = f"listen_addresses = {listen}\nssl = on\n"
    assert statuses("postgresql", postgres_host(conf=conf))["postgres.listen_addresses_not_all_interfaces"] == expected


@pytest.mark.parametrize("ssl, expected", [("on", "pass"), ("off", "fail")])
def test_postgresql_ssl_enabled(ssl, expected):
    conf = f"listen_addresses = 'localhost'\nssl = {ssl}\n"
    assert statuses("postgresql", postgres_host(conf=conf))["postgres.ssl_enabled"] == expected


def test_postgresql_ssl_not_set_defaults_to_off_not_a_false_pass():
    # Официальное умолчание PostgreSQL для ssl — off; отсутствие строки не должно выглядеть как «включено».
    conf = "listen_addresses = 'localhost'\n"
    assert statuses("postgresql", postgres_host(conf=conf))["postgres.ssl_enabled"] == "fail"


@pytest.mark.parametrize("version, expected", [
    ("'TLSv1.2'", "pass"), ("'TLSv1.3'", "pass"), ("'TLSv1'", "fail"), ("'TLSv1.1'", "fail"), ("'SSLv3'", "fail"),
])
def test_postgresql_ssl_min_protocol_version(version, expected):
    conf = f"listen_addresses = 'localhost'\nssl = on\nssl_min_protocol_version = {version}\n"
    assert statuses("postgresql", postgres_host(conf=conf))["postgres.ssl_min_protocol_version_modern"] == expected


@pytest.mark.parametrize("mode, expected", [(0o100640, "pass"), (0o100600, "pass"), (0o100644, "fail"), (0o100664, "fail")])
def test_postgresql_log_permissions(mode, expected):
    assert statuses("postgresql", postgres_host(log_mode=mode))["postgres.log_directory_not_world_readable"] == expected


@pytest.mark.parametrize("mode, expected", [(0o40700, "pass"), (0o40750, "fail"), (0o40755, "fail")])
def test_postgresql_data_directory_permissions(mode, expected):
    assert statuses("postgresql", postgres_host(data_mode=mode))["postgres.data_directory_permissions"] == expected


def test_postgresql_pack_is_a_draft_and_says_so():
    pack = PACKS["postgresql"]
    assert pack.maturity == "draft" and pack.verified_on == [] and pack.transport == "local"


# ============================== Несколько паков на актив ==============================

def all_local_manifests():
    return [MANIFESTS[name] for name in sorted(MANIFESTS) if PACKS[name].transport == "local"]


def test_ubuntu_with_docker_matches_both_packs_and_not_astra():
    host = docker_host({"aaa111bbb222": "false"})
    matched = [m["pack"] for m in probes.select_manifests(host, all_local_manifests())]
    assert matched == ["docker", "ubuntu-server"]


def test_ubuntu_without_docker_matches_only_the_os_pack():
    matched = [m["pack"] for m in probes.select_manifests(docker_host(with_socket=False), all_local_manifests())]
    assert matched == ["ubuntu-server"]


def test_ubuntu_with_samba_matches_the_samba_pack_and_it_does_not_change_the_os_result():
    """1.2.0: Samba — отдельный пак. Есть smb.conf — применяется и он; нет — пак не применяется,
    и проверка Samba не превращается в error на серверах без Samba (как было в ubuntu-server 1.1.0)."""
    host = docker_host(with_socket=False)
    host.files["/etc/samba/smb.conf"] = "[share]\n   path = /srv/share\n   guest ok = yes\n"
    matched = probes.select_manifests(host, all_local_manifests())
    assert [m["pack"] for m in matched] == ["samba", "ubuntu-server"]
    assert statuses("samba", host) == {"filesharing.smb_no_guest_access": "fail"}
    assert "filesharing.smb_no_guest_access" not in statuses("ubuntu-server", host)


def _run_payload(host, name_filter=None):
    matched = probes.select_manifests(host, all_local_manifests())
    return {
        "environment": "prod",
        "asset": {"hostname": "multi-01", "asset_type": "linux-server"},
        "platform_tags": sorted({t for m in matched for t in m["tags"]}),
        "packs": [{"id": m["pack"], "version": m["version"], "probe_results": probes.run_manifest(host, m)} for m in matched],
    }


def test_several_packs_are_evaluated_in_one_ingest_with_one_snapshot(client, db, make_org, make_agent_key):
    key = make_agent_key(make_org("Multi Org"))
    payload = _run_payload(docker_host({"aaa111bbb222": "true"}))

    body = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": key}).json()

    assert body["checks"] == {"total": 20, "passed": 19, "failed": 1, "errors": 0}  # 13 от ОС-пака + 7 от docker (6 pass + privileged fail)
    by_pack = {p["id"]: p for p in body["packs"]}
    assert (by_pack["docker"]["total"], by_pack["docker"]["failed"], by_pack["docker"]["maturity"]) == (7, 1, "baseline")
    assert (by_pack["ubuntu-server"]["total"], by_pack["ubuntu-server"]["passed"]) == (13, 13)
    assert db.execute(text("SELECT COUNT(*) FROM scan_snapshots")).scalar() == 1
    rows = db.execute(text("SELECT pack_id, COUNT(*) FROM hardening_checks GROUP BY pack_id ORDER BY pack_id")).all()
    assert [tuple(r) for r in rows] == [("docker", 7), ("ubuntu-server", 13)]


def test_a_later_run_without_a_pack_drops_that_packs_current_state(client, db, make_org, make_agent_key):
    key = make_agent_key(make_org("Drop Org"))
    client.post("/api/ingest", json=_run_payload(docker_host({})), headers={"X-Agent-Api-Key": key})
    assert db.execute(text("SELECT COUNT(*) FROM hardening_checks")).scalar() == 20  # 13 от ОС-пака + 7 от docker (0 контейнеров -> все проверки pass)

    client.post("/api/ingest", json=_run_payload(docker_host(with_socket=False)), headers={"X-Agent-Api-Key": key})

    assert db.execute(text("SELECT COUNT(*) FROM hardening_checks")).scalar() == 13  # docker удалён с хоста — его проверок нет
    assert db.execute(text("SELECT COUNT(*) FROM scan_snapshots")).scalar() == 2  # история сохранена


def test_same_pack_twice_in_one_run_is_rejected_without_side_effects(client, db, make_org, make_agent_key):
    key = make_agent_key(make_org("Dup Org"))
    payload = _run_payload(docker_host({}))
    payload["packs"].append(payload["packs"][0])

    resp = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": key})

    assert resp.status_code == 422 and "больше одного раза" in resp.json()["detail"]
    assert db.execute(text("SELECT COUNT(*) FROM assets")).scalar() == 0


def test_legacy_single_pack_field_combines_with_packs_list(client, make_org, make_agent_key):
    key = make_agent_key(make_org("Mixed Org"))
    payload = _run_payload(docker_host({}))
    docker_run = next(r for r in payload["packs"] if r["id"] == "docker")
    payload["packs"].remove(docker_run)
    payload["pack"] = {"id": "docker", "version": docker_run["version"]}  # прежний формат: один пак + probe_results
    payload["probe_results"] = docker_run["probe_results"]

    body = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": key}).json()

    assert {p["id"] for p in body["packs"]} == {"docker", "ubuntu-server"}


def test_inventory_pack_and_os_pack_do_not_distort_each_other(client, make_org, make_agent_key):
    """Astra (inventory) рядом с реальным паком: оценка считается только по реальным проверкам."""
    key = make_agent_key(make_org("Inv Org"))
    payload = {
        "environment": "prod", "asset": {"hostname": "astra-01", "asset_type": "linux-server"},
        "platform_tags": ["linux-server", "debian-family", "astra"],
        "packs": [{"id": "astra-linux", "version": "1.0.0", "probe_results": {}}],
    }
    body = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": key}).json()

    assert body["checks"]["total"] == 0 and body["compliance_score"] is None  # «не оценивается», а не «100 %»
    assert body["packs"] == [{"id": "astra-linux", "version": "1.0.0", "maturity": "inventory", "total": 0, "passed": 0, "failed": 0, "errors": 0}]
