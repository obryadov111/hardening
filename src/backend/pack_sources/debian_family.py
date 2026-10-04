"""Паки debian-server и astra-linux из проверок ubuntu-server — единственного источника общих проверок.

    python pack_sources/debian_family.py app/packs     # из каталога src/backend

У Debian 11–13 и Astra Linux SE 1.8 раскладка файлов для этих проверок та же, что у Ubuntu (common-auth,
common-password, sshd_config с Include, login.defs, pwquality.conf, ufw, 20auto-upgrades) — сверено на
официальных образах 2026-09-27. Поэтому проверки не копируются руками, а берутся из последней версии
ubuntu-server: правка проверки там + перегенерация = одинаковая проверка во всех трёх паках.
tests/test_pack_sources.py следит, чтобы YAML в app/packs совпадал с результатом генерации.

Ubuntu эти паки не распознают (detect по ID), иначе проверки считались бы на Ubuntu дважды.
"""
import sys
from pathlib import Path

import yaml

BACKEND = Path(__file__).resolve().parents[1]
FSTEC = "Методика анализа защищённости информационных систем, ФСТЭК России, 25.11.2025"
UBUNTU_CIS = "CIS Benchmark (Ubuntu Linux, адаптировано)"


def ubuntu_checks() -> tuple[str, list[dict]]:
    """Проверки последней версии ubuntu-server (как данные YAML) и её версия."""
    files = sorted(BACKEND.glob("app/packs/ubuntu-server-*.yaml"),
                   key=lambda p: tuple(int(x) for x in p.stem.rsplit("-", 1)[1].split(".")))
    data = yaml.safe_load(files[-1].read_text(encoding="utf-8"))
    return data["version"], data["checks"]


def _with_refs(checks: list[dict], cis_source: str) -> list[dict]:
    result = []
    for check in checks:
        refs = [({"source": cis_source} if ref.get("source") == UBUNTU_CIS else ref) for ref in check.get("refs", [])]
        result.append({**check, "refs": refs})
    return result


PACKS = {
    "debian-server": {
        "version": "1.1.0",
        "tags": ["linux-server", "debian-family", "debian"],
        "detect": [{"probe": {"type": "file_kv", "path": "/etc/os-release", "key": "ID", "separator": "equals"}, "equals": "debian"}],
        "cis": "CIS Debian Linux Benchmark (адаптировано)",
        "header": """# Пак «Debian»: Debian 11 (bullseye), 12 (bookworm), 13 (trixie). Распознаётся по ID=debian.
#
# Проверки — те же, что у ubuntu-server {ubuntu_version} (генерируются из него, pack_sources/debian_family.py):
# раскладка файлов для них у Debian та же — сверено на официальных образах Debian 11/12/13 2026-09-27.
# Отличие Debian от Ubuntu на практике: ufw и unattended-upgrades по умолчанию не установлены (в Debian
# межсетевой экран чаще — nftables напрямую). Нет ufw — проверки межсетевого экрана «не проверено»
# (нет файлов), а не «соблюдено»; используется nftables — оформить исключение.
#
# maturity=draft: агент выполнен в контейнерах Debian 11/12/13 — пак распознан, файловые пробы
# выполняются на настоящих файлах ОС; службы (auditd) без systemd в контейнере не подтверждены.
""",
    },
    "astra-linux": {
        "version": "1.2.0",
        "tags": ["linux-server", "debian-family", "astra"],
        # Детект прежний (1.0.0): вхождение «astra» в ID/NAME/PRETTY_NAME. На образе 1.8.6: ID=astra.
        "detect": [{"probe": {"type": "file_regex", "path": "/etc/os-release",
                              "pattern": '(?im)^(?:ID|NAME|PRETTY_NAME)="?([^"\n]*astra[^"\n]*)'}, "regex": "(?i)astra"}],
        "cis": "CIS Debian Linux Benchmark (адаптировано; Astra Linux основана на Debian)",
        "header": """# Пак «Astra Linux Special Edition»: 1.8 (сверено на официальном образе 1.8.6 из registry.astralinux.ru).
# Распознаётся по вхождению «astra» в ID/NAME/PRETTY_NAME /etc/os-release (на 1.8.6 — ID=astra).
#
# 1.1.0 (2026-09-27): было «только обнаружение» (1.0.0, проверок нет — без реального образа их нельзя было
# писать). Образ появился: общие для Debian проверки подтверждены на настоящих файлах Astra 1.8.6 — раскладка
# та же, что у Ubuntu/Debian (common-auth, common-password, sshd_config, login.defs, pwquality.conf, ufw,
# 20auto-upgrades). Проверки генерируются из ubuntu-server {ubuntu_version} (pack_sources/debian_family.py).
# Особенности Astra, замеченные на образе: пароли хэшируются ГОСТ (gost12_512 в common-password),
# pam_pwquality подключён по умолчанию, ufw и автообновления установлены и настроены как в Ubuntu.
#
# НЕ проверяются собственные механизмы защиты Astra: мандатный контроль целостности (МКЦ), мандатное
# управление доступом (МРД), замкнутая программная среда (ЗПС), режимы защищённости — они работают в ядре
# (parsec) и в контейнере не наблюдаемы; команды их проверки пишутся по руководству вендора на реальной
# установке, не по памяти. Это следующий шаг, для него нужна виртуальная машина Astra.
#
# maturity=draft: агент выполнен в контейнере Astra 1.8.6 — пак распознан, файловые пробы выполняются;
# службы без systemd не подтверждены.
""",
    },
}


def build(pack_id: str) -> tuple[str, dict]:
    spec = PACKS[pack_id]
    ubuntu_version, checks = ubuntu_checks()
    pack = {
        "pack": pack_id,
        "version": spec["version"],
        "maturity": "draft",
        "tags": spec["tags"],
        "transport": "local",
        "asset_type": "linux-server",
        "detect": spec["detect"],
        "checks": _with_refs(checks, spec["cis"]),
    }
    return spec["header"].format(ubuntu_version=ubuntu_version), pack


def render(pack_id: str) -> str:
    header, pack = build(pack_id)
    return header + "\n" + yaml.safe_dump(pack, allow_unicode=True, sort_keys=False, width=200)


if __name__ == "__main__":
    out = Path(sys.argv[1])
    for pack_id in PACKS:
        path = out / f"{pack_id}-{PACKS[pack_id]['version']}.yaml"
        path.write_text(render(pack_id), encoding="utf-8")
        print(path.name, len(build(pack_id)[1]["checks"]), "проверок")
