"""Регрессия: старый агент (collector.py + 14 правил hardening_rules) против пака ubuntu-server.

Один и тот же смоделированный хост прогоняется обоими путями; статусы сравниваются по каждому из
12 общих правил. Расходиться пути могут ТОЛЬКО там, где старая логика неверна, и каждое такое
расхождение перечислено в DEVIATIONS с точной парой статусов (старый, новый) и причиной. Любое
непредусмотренное расхождение — провал теста; изменившееся расхождение — тоже."""
import fnmatch
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.hardening_engine import evaluate_asset
from app.services.packs.evaluate import evaluate_pack
from app.services.packs.manifest import build_manifest
from app.services.packs.registry import load_registry

REPO = Path(__file__).resolve().parents[3]
AGENT_DIR = REPO / "agent"
if not (AGENT_DIR / "probes.py").exists():
    pytest.skip("каталог agent/ недоступен (тесты запущены вне репозитория)", allow_module_level=True)
sys.path.insert(0, str(AGENT_DIR))

import collector  # noqa: E402
import probes  # noqa: E402

BACKEND = REPO / "src" / "backend"
PACK = load_registry(BACKEND / "app" / "packs").get("ubuntu-server")
MANIFEST = build_manifest(PACK)


def _load_legacy_rules():
    path = BACKEND / "alembic" / "versions" / "df4fc6d56bf8_seed_starter_hardening_rules.py"
    spec = importlib.util.spec_from_file_location("legacy_seed", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return [
        SimpleNamespace(id=code, rule_code=code, expected_value=expected, product_type=None)
        for code, _title, expected, _severity, _remediation in module.RULES
    ]


LEGACY_RULES = _load_legacy_rules()
_LEGACY_CODES = {rule.rule_code for rule in LEGACY_RULES}
# Подмножество проверок пака, у которых есть прямой аналог в старом агенте (12 правил, перенесённых
# на этапе 1). С 1.1.0 в паке есть и проверки без аналога в старом агенте (см. NEW_CHECKS ниже) —
# они намеренно не входят в SHARED и не участвуют в сравнении со старой логикой.
SHARED = sorted(check.id for check in PACK.checks if check.id in _LEGACY_CODES)
# Проверки без аналога в старом агенте (добавлены в 1.1.0 по методике ФСТЭК от 25.11.2025, раздел ОПС) —
# не сравниваются со старой логикой и тестируются отдельно ниже. filesharing.smb_no_guest_access
# с 1.2.0 — в отдельном паке samba (образцы: pack_tests/samba.yaml).
NEW_CHECKS = {"logging.auditd_active"}
# Намеренные отличия критичности от сида старого агента: 1.2.0, сверка с методикой оценки
# критичности ФСТЭК от 30.06.2025 (правило — README паков). Любое другое расхождение — провал.
SEVERITY_CHANGES = {
    "firewall.ufw_enabled": ("critical", "high"),
    "ssh.permit_root_login": ("critical", "high"),
}


class FakeHost:
    """Смоделированный хост: файлы и команды. Даёт оба интерфейса — старого сборщика и транспорта проб."""

    name = "local"

    def __init__(self, files: dict, commands: dict):
        self.files, self.commands = files, commands  # commands: "ufw status verbose" -> (stdout, stderr, code)

    # старый сборщик: None, если файла нет / команда завершилась с ошибкой
    def legacy_read_file(self, path):
        return self.files.get(path)

    def legacy_run(self, cmd):
        result = self.commands.get(" ".join(cmd))
        return result[0] if result and result[2] == 0 else None

    # транспорт проб
    def read_file(self, path):
        if path not in self.files:
            raise probes.ProbeError(f"нет файла {path}")
        return self.files[path]

    def glob(self, pattern):
        return sorted(p for p in self.files if fnmatch.fnmatch(p, pattern))

    def run(self, argv):
        result = self.commands.get(" ".join(argv))
        if result is None:
            raise probes.ProbeError(f"команда {argv[0]} не найдена")
        return probes.CmdOutput(*result)


UFW_ACTIVE = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"
NEEDS_ROOT = ("", "ERROR: You need to be root to run this script", 1)

HARDENED_FILES = {
    "/etc/os-release": "ID=ubuntu\n",
    "/etc/ssh/sshd_config": "PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\nX11Forwarding no\nMaxAuthTries 4\n",
    "/etc/ufw/ufw.conf": "ENABLED=yes\n",
    "/etc/default/ufw": 'DEFAULT_INPUT_POLICY="DROP"\n',
    "/etc/apt/apt.conf.d/20auto-upgrades": 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n',
    "/etc/login.defs": "PASS_MAX_DAYS\t90\nPASS_MIN_DAYS\t0\n",
    "/etc/security/pwquality.conf": "# comment\nminlen = 14\n",
    "/etc/pam.d/common-auth": "auth required pam_faillock.so preauth deny=5\nauth [success=1] pam_unix.so\n",
    "/proc/sys/net/ipv4/ip_forward": "0\n",
}
HARDENED_COMMANDS = {"ufw status verbose": (UFW_ACTIVE, "", 0), "systemctl is-active auditd": ("active\n", "", 0)}


def make_host(files=None, commands=None, drop=()):
    merged_files = {**HARDENED_FILES, **(files or {})}
    for path in drop:
        merged_files.pop(path, None)
    return FakeHost(merged_files, {**HARDENED_COMMANDS, **(commands or {})})


def legacy_statuses(host, monkeypatch):
    monkeypatch.setattr(collector, "read_file", host.legacy_read_file)
    monkeypatch.setattr(collector, "run", host.legacy_run)
    results = evaluate_asset(collector.collect_facts(), LEGACY_RULES, asset_type="server")
    return {r.rule_code: r.status for r in results if r.rule_code in SHARED}


def pack_statuses(host):
    raw = probes.run_manifest(host, MANIFEST)
    results = evaluate_pack(PACK, {k: SimpleNamespace(**v) for k, v in raw.items()})
    return {r.check_id: r.status for r in results}


UNHARDENED_FILES = {
    "/etc/ssh/sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\nX11Forwarding yes\nMaxAuthTries 10\n",
    "/etc/ufw/ufw.conf": "ENABLED=no\n",
    "/etc/default/ufw": 'DEFAULT_INPUT_POLICY="ACCEPT"\n',
    "/etc/apt/apt.conf.d/20auto-upgrades": 'APT::Periodic::Unattended-Upgrade "0";\n',
    "/etc/login.defs": "PASS_MAX_DAYS\t99999\n",
    "/etc/security/pwquality.conf": "minlen = 8\n",
    "/etc/pam.d/common-auth": "auth [success=1] pam_unix.so\n",
    "/proc/sys/net/ipv4/ip_forward": "1\n",
}

# (сценарий) -> хост. Первые четыре — где старый агент прав: пути обязаны совпасть полностью.
IDENTICAL = {
    "hardened": make_host,
    "unhardened": lambda: make_host(UNHARDENED_FILES, {"ufw status verbose": ("Status: inactive\n", "", 0)}),
    # ufw status недоступен без root: состояние берётся из файлов, оба пути обязаны сойтись
    "no_root_fallback_bad": lambda: make_host(
        {"/etc/ufw/ufw.conf": "ENABLED=no\n", "/etc/default/ufw": 'DEFAULT_INPUT_POLICY="ACCEPT"\n'},
        {"ufw status verbose": NEEDS_ROOT},
    ),
    # голый контейнер: почти ничего нет — error по большинству правил у обоих путей
    "bare_container": lambda: make_host(drop=[p for p in HARDENED_FILES if p not in ("/etc/os-release", "/proc/sys/net/ipv4/ip_forward")],
                                        commands={"ufw status verbose": NEEDS_ROOT}),
    # ufw включён по файлу конфигурации, политика в статусе не выводится — сходятся оба пути
    "no_root_enabled_accept": lambda: make_host(
        {"/etc/default/ufw": 'DEFAULT_INPUT_POLICY="ACCEPT"\n'}, {"ufw status verbose": NEEDS_ROOT}
    ),
}


@pytest.mark.parametrize("scenario", IDENTICAL)
def test_old_agent_and_pack_agree_where_the_old_logic_is_correct(scenario, monkeypatch):
    host = IDENTICAL[scenario]()

    old, new_all = legacy_statuses(host, monkeypatch), pack_statuses(host)
    new = {code: status for code, status in new_all.items() if code in SHARED}

    assert set(new) == set(SHARED)
    assert old == new, {c: (old.get(c), new.get(c)) for c in SHARED if old.get(c) != new.get(c)}


def test_scenarios_cover_all_three_outcomes():
    """Страховка от вырожденных сценариев: без pass, fail и error сравнение ничего не доказывает."""
    seen = set()
    for build in IDENTICAL.values():
        seen |= set(pack_statuses(build()).values())
    assert seen == {"pass", "fail", "error"}


# Каждое расхождение: (сценарий, правило) -> (статус старого агента, статус пака). Причина — в комментарии.
DEVIATIONS = [
    pytest.param(
        "strict_values_flagged_by_old_equality",
        lambda: make_host({
            "/etc/ssh/sshd_config": HARDENED_FILES["/etc/ssh/sshd_config"].replace("MaxAuthTries 4", "MaxAuthTries 3"),
            "/etc/login.defs": "PASS_MAX_DAYS\t60\n",
            "/etc/security/pwquality.conf": "minlen = 16\n",
        }),
        {
            # старые правила требовали РОВНО 4 / 90 / 14: более строгая настройка считалась нарушением
            "ssh.max_auth_tries": ("fail", "pass"),
            "password_policy.pass_max_days": ("fail", "pass"),
            "password_policy.pass_min_len": ("fail", "pass"),
        },
        id="строгие значения",
    ),
    pytest.param(
        "ssh_default_root_login",
        lambda: make_host({"/etc/ssh/sshd_config": "# всё по умолчанию\n"}),
        {
            # старый агент считал умолчанием PermitRootLogin no; у OpenSSH это prohibit-password (ложный pass)
            "ssh.permit_root_login": ("pass", "fail"),
        },
        id="умолчание PermitRootLogin",
    ),
    pytest.param(
        "faillock_conf_only_comments",
        lambda: make_host(
            {"/etc/pam.d/common-auth": "auth [success=1] pam_unix.so\n",
             "/etc/security/faillock.conf": "# deny = 3\n# unlock_time = 600\n"}
        ),
        {
            # непустой faillock.conf из одних комментариев при неподключённом pam_faillock: блокировки нет,
            # а старый агент выставлял «включена» (ложный pass) — реальная ситуация на стандартной Ubuntu
            "password_policy.lockout_on_failure": ("pass", "fail"),
        },
        id="faillock.conf из комментариев",
    ),
    pytest.param(
        "pam_faillock_commented_out",
        lambda: make_host({"/etc/pam.d/common-auth": "# auth required pam_faillock.so preauth deny=5\nauth [success=1] pam_unix.so\n"}),
        {
            # строка pam_faillock закомментирована — блокировка не работает, но старый агент искал подстроку
            # «pam_faillock» в файле целиком и засчитывал комментарий (ложный pass)
            "password_policy.lockout_on_failure": ("pass", "fail"),
        },
        id="pam_faillock закомментирован",
    ),
    pytest.param(
        "ufw_reject_policy",
        lambda: make_host(commands={"ufw status verbose": (UFW_ACTIVE.replace("deny (incoming)", "reject (incoming)"), "", 0)}),
        {"firewall.default_incoming_policy": ("fail", "pass")},  # reject тоже запрещает входящие
        id="политика reject",
    ),
    pytest.param(
        "ufw_drop_in_defaults_file",
        lambda: make_host(commands={"ufw status verbose": NEEDS_ROOT}),
        {
            # /etc/default/ufw записывает запрет как DROP; старый агент не приравнивал его к deny.
            # ufw_enabled здесь по-прежнему совпадает (ENABLED=yes -> pass у обоих)
            "firewall.default_incoming_policy": ("fail", "pass"),
        },
        id="DROP в /etc/default/ufw",
    ),
    pytest.param(
        "sshd_include_first_match_and_match_block",
        lambda: make_host({
            "/etc/ssh/sshd_config": (
                "Include /etc/ssh/sshd_config.d/*.conf\n"
                "PermitRootLogin yes\n"            # sshd: первое значение (из drop-in) уже победило
                "PasswordAuthentication no\n"
                "Match User backup\n"
                "    PasswordAuthentication yes\n"  # условный блок, не глобальное значение
            ),
            "/etc/ssh/sshd_config.d/50-hardening.conf": "PermitRootLogin no\n",
        }),
        {
            # старый агент не читает Include, берёт последнее вхождение и строки внутри Match
            "ssh.permit_root_login": ("fail", "pass"),
            "ssh.password_authentication": ("fail", "pass"),
        },
        id="Include, первое значение, Match",
    ),
]


@pytest.mark.parametrize("name, build, deviations", DEVIATIONS)
def test_every_deviation_is_exactly_the_documented_one(name, build, deviations, monkeypatch):
    host = build()

    old, new = legacy_statuses(host, monkeypatch), pack_statuses(host)

    actual = {code: (old[code], new[code]) for code in SHARED if old[code] != new[code]}
    assert actual == deviations, f"{name}: расхождения изменились"


def test_deviations_only_ever_make_the_pack_more_correct_never_hide_a_finding_the_old_agent_saw():
    """Из всех задокументированных расхождений «pass у старого агента, fail у пака» — это исправление
    ложных прохождений; обратное («fail -> pass») допустимо только там, где старое правило было
    строже нормы. Проверяем, что список не содержит непредусмотренных направлений."""
    allowed_pass_to_fail = {"ssh.permit_root_login", "password_policy.lockout_on_failure"}
    seen_pass_to_fail = set()
    for param in DEVIATIONS:
        for code, (old, new) in param.values[2].items():
            if (old, new) == ("pass", "fail"):
                seen_pass_to_fail.add(code)
    assert seen_pass_to_fail == allowed_pass_to_fail


def test_shipped_pack_covers_exactly_the_twelve_migrated_rules_plus_known_new_checks():
    legacy_codes = {rule.rule_code for rule in LEGACY_RULES}
    assert set(SHARED) < legacy_codes  # пак — собственное подмножество прежних правил
    assert legacy_codes - set(SHARED) == {"docker.no_privileged_containers", "postgres.ssl_enabled"}
    # Коды сверх старых 14 правил допустимы, только если это именно NEW_CHECKS (сверка с методикой
    # ФСТЭК) — а не случайное расширение пака.
    all_ids = {check.id for check in PACK.checks}
    assert all_ids - legacy_codes == NEW_CHECKS
    assert all(check.id in legacy_codes | NEW_CHECKS for check in PACK.checks)


def test_pack_metadata_matches_legacy_rules():
    """Название-смысл и критичность перенесены без потерь: критичность совпадает с сидом, кроме
    задокументированных изменений SEVERITY_CHANGES (и только в ту сторону, что там указана)."""
    legacy = importlib.util.spec_from_file_location(
        "legacy_seed2", BACKEND / "alembic" / "versions" / "df4fc6d56bf8_seed_starter_hardening_rules.py"
    )
    module = importlib.util.module_from_spec(legacy)
    legacy.loader.exec_module(module)
    severities = {code: severity for code, _t, _e, severity, _r in module.RULES}
    # Сравнение — только по проверкам с аналогом в старом агенте; новые проверки 1.1.0 в сиде не было.
    migrated = {c.id: c.severity for c in PACK.checks if c.id in SHARED}
    expected = {code: severities[code] for code in SHARED}
    for code, (was, now) in SEVERITY_CHANGES.items():
        assert expected[code] == was, f"{code}: в сиде ожидалось {was}"
        expected[code] = now
    assert migrated == expected
    assert all(c.remediation for c in PACK.checks)


# ============================== Новое в 1.1.0 (методика ФСТЭК от 25.11.2025, раздел ОПС) ==============================
# Проверки без аналога в старом агенте — не часть регрессии выше, тестируются отдельно:
# pass (эталонный хост), fail (нарушение) и error (компонент не установлен — не ложный pass).

def test_auditd_active_passes_on_the_reference_hardened_host():
    assert pack_statuses(make_host())["logging.auditd_active"] == "pass"


def test_auditd_inactive_fails():
    host = make_host(commands={"systemctl is-active auditd": ("inactive\n", "", 3)})
    assert pack_statuses(host)["logging.auditd_active"] == "fail"


def test_auditd_unit_not_found_fails_not_a_false_pass():
    # Юнит auditd.service отсутствует: systemctl пишет сообщение в stderr, а не пустой вывод —
    # пробa находит текст ошибки как значение, и "!= active" даёт честный fail, а не пустой (error) статус.
    host = make_host(commands={"systemctl is-active auditd": ("", "Unit auditd.service could not be found.\n", 4)})
    assert pack_statuses(host)["logging.auditd_active"] == "fail"


# Проверка Samba с 1.2.0 — в паке samba: pass/fail/синонимы/комментарии/«не установлена» — pack_tests/samba.yaml.


def test_new_checks_are_disjoint_from_the_legacy_regression_suite():
    """Страховка: новые проверки не должны случайно попасть в SHARED и исказить регрессию со старым агентом."""
    assert NEW_CHECKS.isdisjoint(SHARED)
    assert NEW_CHECKS == {c.id for c in PACK.checks if c.id not in SHARED}
