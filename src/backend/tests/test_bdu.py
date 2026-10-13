"""БДУ ФСТЭК: версии, сопоставление пакетов, уровень критичности по методике, загрузка выгрузки, API."""
import json
import uuid
import zipfile

import pytest
from sqlalchemy import text

from app.services.bdu.criticality import criticality, impact_of, level_of
from app.services.bdu.importer import import_bdu
from app.services.bdu.matching import LEVEL_ORDER, organization_vulnerabilities
from app.services.bdu.products import not_compared_reason, product_for_package
from app.services.bdu.ubuntu_oval import distro_status, import_oval, parse_oval, ubuntu_release
from app.services.bdu.versions import compare, compare_deb, parse_bdu_version, upstream_version

# ---------- версии ----------


@pytest.mark.parametrize(("a", "b", "expected"), [
    ("7.1p2", "7.1", 1),        # OpenSSH: p-релиз — после базовой версии
    ("7.1p2", "7.2", -1),
    ("1.2", "1.2.0", 0),
    ("2.0.0", "2.0rc1", 1),     # предварительная версия — раньше релиза
    ("5.4.5", "5.6.0", -1),
    ("1.0.1j", "1.0.1", 1),
    ("10.0", "9.9", 1),         # числа сравниваются как числа, а не как строки
])
def test_compare(a, b, expected):
    assert compare(a, b) == expected


@pytest.mark.parametrize(("deb", "upstream"), [
    ("1:9.6p1-3ubuntu13.19", "9.6p1"),
    ("5.6.1+really5.4.5-1ubuntu0.3", "5.4.5"),   # xz-utils: подменённая версия
    ("2.9.14+dfsg-1.3ubuntu3.9", "2.9.14"),
    ("1.35+dfsg-3ubuntu0.4", "1.35"),
    ("2:9.1.0016-1ubuntu7.20", "9.1.0016"),
    ("1.9.15p5-3ubuntu5.24.04.3", "1.9.15p5"),
    ("3.45.1", "3.45.1"),
])
def test_upstream_version(deb, upstream):
    assert upstream_version(deb) == upstream


@pytest.mark.parametrize(("expr", "inside", "outside"), [
    ("от 9.0.0 до 9.0.12 включительно", ["9.0.0", "9.0.12"], ["8.9", "9.0.13"]),
    ("от 8.6 до 9.8", ["8.6", "9.6p1"], ["9.8", "8.5"]),     # верхняя граница «до» не включается
    ("до 1.9.17p1", ["1.9.15p5"], ["1.9.17p1", "1.9.18"]),
    ("до версии 7.4", ["7.3"], ["7.4"]),
    ("3.7.2", ["3.7.2"], ["3.7.3"]),
])
def test_bdu_version_ranges(expr, inside, outside):
    parsed = parse_bdu_version(expr)
    assert all(parsed.contains(v) for v in inside)
    assert not any(parsed.contains(v) for v in outside)


@pytest.mark.parametrize("expr", ["-", "20.04 LTS", "1.7 «Смоленск»", "Server 2019", ""])
def test_non_version_expressions_are_skipped(expr):
    assert parse_bdu_version(expr) is None


# ---------- пакеты → продукты ----------


@pytest.mark.parametrize(("package", "product"), [
    ("openssh-server", "openssh"),
    ("libssl3t64", "openssl"),
    ("libc6", "glibc"),
    ("xz-utils", "xz utils"),
    ("python3.12", "python"),
    ("rsync", "rsync"),            # совпадение имени целиком
])
def test_product_for_package(package, product):
    assert product_for_package(package) == product


def test_kernel_and_firefox_are_not_compared_with_a_reason():
    assert product_for_package("linux-image-6.8.0-142-generic") is None
    assert "ядро" in not_compared_reason("linux-image-6.8.0-142-generic")
    assert product_for_package("firefox") is None


# ---------- уровень критичности по методике ФСТЭК от 30.06.2025 ----------


def test_criticality_formula():
    # Сервер (K 0.7), единственный актив (L 1.0), недоступен из интернета (P 0.6):
    # Iinfr = 0.5·0.7 + 0.2·1.0 + 0.3·0.6 = 0.73; эксплойт есть (0.3); выполнение кода (0.5).
    crit = criticality(
        cvss3=9.8, cvss2=10.0, asset_type="linux-server", affected_assets=1, total_assets=1,
        internet_facing=False, exploit_status="Существует в открытом доступе", incident="Данные уточняются",
        name="Уязвимость …, позволяющая нарушителю выполнить произвольный код",
    )
    assert (crit.icvss, crit.cvss_version, crit.iinfr, crit.iat, crit.iimp) == (9.8, "3", 0.73, 0.3, 0.5)
    assert crit.v == 5.72 and crit.level == "high"


def test_criticality_internet_exposure_and_real_attacks_raise_v():
    common = dict(cvss3=9.8, cvss2=None, asset_type="linux-server", affected_assets=1, total_assets=1,
                  name="позволяющая выполнить произвольный код")
    quiet = criticality(internet_facing=False, exploit_status="Данные уточняются", incident="Данные уточняются", **common)
    exposed = criticality(internet_facing=True, exploit_status="Существует", incident="Да", **common)
    assert exposed.v > quiet.v and exposed.level == "critical"  # 9.8 × 0.88 × 1.1 = 9.49


def test_cvss2_fallback_and_unscored():
    crit = criticality(cvss3=None, cvss2=7.5, asset_type=None, affected_assets=1, total_assets=4,
                       internet_facing=False, exploit_status=None, incident=None, name="")
    assert crit.cvss_version == "2" and crit.iinfr == round(0.5 * 0.1 + 0.2 * 0.6 + 0.3 * 0.6, 3)
    assert criticality(cvss3=None, cvss2=None, asset_type=None, affected_assets=1, total_assets=1,
                       internet_facing=False, exploit_status=None, incident=None, name="") is None


@pytest.mark.parametrize(("name", "label"), [
    ("позволяющая нарушителю вызвать отказ в обслуживании", "отказ в обслуживании"),
    ("позволяющая нарушителю повысить свои привилегии", "повышение привилегий"),
    ("позволяющая нарушителю раскрыть защищаемую информацию", "получение защищаемой информации"),
    ("позволяющая проводить межсайтовые сценарные атаки", "межсайтовый скриптинг"),
    ("Уязвимость без описания последствий", "последствия не распознаны"),
])
def test_impact_from_name(name, label):
    assert impact_of(name)[0] == label


@pytest.mark.parametrize(("v", "level"), [(8.01, "critical"), (8.0, "high"), (5.0, "high"), (4.99, "medium"), (2.0, "medium"), (1.99, "low")])
def test_levels(v, level):
    assert level_of(v) == level


# ---------- загрузка выгрузки и API ----------

SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<vulnerabilities>
 <vul><identifier>BDU:2024-04914</identifier>
  <name>Уязвимость OpenSSH, позволяющая нарушителю выполнить произвольный код</name>
  <vulnerable_software>
   <soft><name>OpenSSH</name><vendor>The OpenBSD Project</vendor><version>от 8.6 до 9.8</version></soft>
   <soft><name>Ubuntu</name><vendor>Canonical</vendor><version>24.04 LTS</version></soft>
  </vulnerable_software>
  <cvss><vector score="10">AV:N/AC:L/Au:N/C:C/I:C/A:C</vector></cvss>
  <cvss3><vector score="8,1">AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</vector></cvss3>
  <publication_date>01.07.2024</publication_date><exploit_status>Существует</exploit_status>
  <fix_status>Уязвимость устранена</fix_status><solution>Обновить OpenSSH</solution>
  <identifiers><identifier type="CVE" link="x">CVE-2024-6387</identifier></identifiers>
  <vul_incident>Данные уточняются</vul_incident>
 </vul>
 <vul><identifier>BDU:2019-00001</identifier>
  <name>Уязвимость OpenSSH, позволяющая нарушителю вызвать отказ в обслуживании</name>
  <vulnerable_software><soft><name>OpenSSH</name><vendor>The OpenBSD Project</vendor><version>до 7.4</version></soft></vulnerable_software>
  <cvss3><vector score="5.3">AV:N</vector></cvss3>
 </vul>
 <vul><identifier>BDU:2026-00001</identifier>
  <name>Уязвимость ядра Linux, позволяющая повысить свои привилегии</name>
  <vulnerable_software><soft><name>Linux</name><vendor>Сообщество</vendor><version>до 7.0</version></soft></vulnerable_software>
  <cvss3><vector score="7.8">AV:L</vector></cvss3>
 </vul>
</vulnerabilities>
"""


@pytest.fixture
def bdu_loaded(db, tmp_path):
    archive = tmp_path / "vulxml.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("export/vulxml.xml", SAMPLE_XML)
    return import_bdu(db, archive)


def test_import_loads_vulnerabilities_and_skips_unversioned_software(db, bdu_loaded):
    assert (bdu_loaded.vulnerabilities, bdu_loaded.software_rows, bdu_loaded.skipped_rows) == (3, 3, 1)
    row = db.execute(text("SELECT cvss3, cvss2, cves, published FROM bdu_vulnerabilities WHERE bdu_id = 'BDU:2024-04914'")).one()
    assert (float(row.cvss3), float(row.cvss2), row.cves, str(row.published)) == (8.1, 10.0, "CVE-2024-6387", "2024-07-01")
    assert db.execute(text("SELECT source, vulnerabilities FROM bdu_imports")).one() == ("vulxml.zip", 3)


def test_reimport_replaces_data(db, bdu_loaded, tmp_path):
    single = tmp_path / "one.xml"
    single.write_text(SAMPLE_XML.split(" <vul><identifier>BDU:2019")[0] + "</vulnerabilities>", encoding="utf-8")
    import_bdu(db, single)
    assert db.execute(text("SELECT count(*) FROM bdu_vulnerabilities")).scalar() == 1


@pytest.fixture
def org_with_host(db, make_org, make_user, add_membership, auth_header):
    org_id = make_org("BDU Org")
    env_id, asset_id = str(uuid.uuid4()), str(uuid.uuid4())
    db.execute(text("INSERT INTO environments (id, organization_id, name) VALUES (:e, :o, 'prod')"), {"e": env_id, "o": org_id})
    db.execute(text("INSERT INTO assets (id, environment_id, hostname, asset_type) VALUES (:a, :e, 'web-01', 'linux-server')"),
               {"a": asset_id, "e": env_id})
    for name, version in [("openssh-server", "1:9.6p1-3ubuntu13.19"), ("openssh-client", "1:9.6p1-3ubuntu13.19"),
                          ("linux-image-6.8.0-142-generic", "6.8.0-142.142"), ("bash", "5.2.21-2ubuntu4")]:
        db.execute(text("INSERT INTO software (asset_id, name, version) VALUES (:a, :n, :v)"), {"a": asset_id, "n": name, "v": version})
    db.commit()
    add_membership(make_user("bdu-viewer@example.com"), org_id)
    return {"id": org_id, "asset_id": asset_id, "headers": auth_header("bdu-viewer@example.com")}


def test_api_lists_potential_vulnerabilities_with_criticality(client, bdu_loaded, org_with_host):
    body = client.get(f"/api/organizations/{org_with_host['id']}/vulnerabilities", headers=org_with_host["headers"]).json()

    # openssh 9.6p1 попадает в «от 8.6 до 9.8», но не в «до 7.4»; ядро не сопоставляется вовсе.
    assert body["total"] == 1 and body["summary"]["medium"] == 1
    (item,) = body["items"]
    assert (item["bdu_id"], item["package"], item["compared_version"], item["cves"]) == (
        "BDU:2024-04914", "openssh-client, openssh-server", "9.6p1", ["CVE-2024-6387"],
    )
    # CVSS 3 = 8.1; Iinfr 0.73; эксплойт есть (0.3) + выполнение кода (0.5): V = 8.1 × 0.73 × 0.8 = 4.73 — средний.
    assert item["criticality"]["v"] == 4.73 and item["level"] == "medium" and item["deadline"] == "до 4 недель"
    assert any("ядро" in n["reason"] for n in body["not_compared"])
    assert body["import"]["vulnerabilities"] == 3


def test_api_requires_organization_access(client, bdu_loaded, org_with_host, make_user, auth_header):
    make_user("stranger@example.com")
    resp = client.get(f"/api/organizations/{org_with_host['id']}/vulnerabilities", headers=auth_header("stranger@example.com"))
    assert resp.status_code == 403


def test_api_without_bdu_returns_empty_result(client, org_with_host):
    body = client.get(f"/api/organizations/{org_with_host['id']}/vulnerabilities", headers=org_with_host["headers"]).json()
    assert body["total"] == 0 and body["import"] is None


# ---------- данные Ubuntu (OVAL Canonical) ----------



@pytest.mark.parametrize(("a", "b", "expected"), [
    ("1:9.6p1-3ubuntu13.19", "1:9.6p1-3ubuntu13.3", 1),   # 13.19 > 13.3: ревизии сравниваются как числа
    ("1.0~rc1", "1.0", -1),                               # «~» раньше релиза
    ("2:1.0", "1:9.9", 1),                                # эпоха важнее версии
    ("0.9.24-4", "0.9.24-4ubuntu0.1~esm1", -1),
    ("1.2.3", "1.2.10", -1),
    ("1.0", "1.0-0", 0),
])
def test_compare_deb(a, b, expected):
    assert compare_deb(a, b) == expected


@pytest.mark.parametrize(("os_name", "release"), [
    ("Ubuntu 24.04.4 LTS", "noble"), ("Ubuntu 22.04.5 LTS", "jammy"), ("Ubuntu 20.04 LTS", "focal"),
    ("Debian GNU/Linux 12", None), (None, None),
])
def test_ubuntu_release(os_name, release):
    assert ubuntu_release(os_name) == release


SAMPLE_OVAL = """<?xml version="1.0" encoding="utf-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
                  xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
 <definitions>
  <definition id="oval:com.ubuntu.noble:def:100" class="inventory" version="1"><metadata><title>noble</title></metadata></definition>
  <definition id="oval:com.ubuntu.noble:def:1" class="vulnerability" version="1">
   <metadata><title>CVE-2024-6387</title><description>long text</description>
    <advisory><cve priority="high" usns="6859-1">CVE-2024-6387</cve></advisory></metadata>
   <criteria><criterion test_ref="tst:1" comment="openssh source package in noble, is affected and has been fixed (note: '1:9.6p1-3ubuntu13.3')." /></criteria>
  </definition>
  <definition id="oval:com.ubuntu.noble:def:2" class="vulnerability" version="1">
   <metadata><title>CVE-2026-1</title><advisory><cve priority="medium">CVE-2026-1</cve></advisory></metadata>
   <criteria><criterion test_ref="tst:2" comment="openssh source package in noble, might be affected and may need fixing." /></criteria>
  </definition>
  <definition id="oval:com.ubuntu.noble:def:3" class="vulnerability" version="1">
   <metadata><title>CVE-2026-2</title><advisory><cve priority="high" usns="9000-1">CVE-2026-2</cve></advisory></metadata>
   <criteria><criterion test_ref="tst:3" comment="openssh source package in noble, is affected and has been fixed (note: '1:9.6p1-3ubuntu13.99~esm1')." /></criteria>
  </definition>
 </definitions>
 <tests>
  <linux-def:dpkginfo_test id="tst:1" version="1"><linux-def:object object_ref="obj:1" /><linux-def:state state_ref="ste:1" /></linux-def:dpkginfo_test>
  <linux-def:dpkginfo_test id="tst:2" version="1"><linux-def:object object_ref="obj:1" /></linux-def:dpkginfo_test>
  <linux-def:dpkginfo_test id="tst:3" version="1"><linux-def:object object_ref="obj:1" /><linux-def:state state_ref="ste:3" /></linux-def:dpkginfo_test>
 </tests>
 <objects>
  <linux-def:dpkginfo_object id="obj:1" version="1"><linux-def:name var_ref="var:1" var_check="at least one" /></linux-def:dpkginfo_object>
 </objects>
 <states>
  <linux-def:dpkginfo_state id="ste:1" version="1"><linux-def:evr datatype="debian_evr_string" operation="less than">1:9.6p1-3ubuntu13.3</linux-def:evr></linux-def:dpkginfo_state>
  <linux-def:dpkginfo_state id="ste:3" version="1"><linux-def:evr datatype="debian_evr_string" operation="less than">1:9.6p1-3ubuntu13.99~esm1</linux-def:evr></linux-def:dpkginfo_state>
 </states>
 <variables>
  <constant_variable id="var:1" version="1" datatype="string"><value>openssh-client</value><value>openssh-server</value></constant_variable>
 </variables>
</oval_definitions>
"""


@pytest.fixture
def oval_file(tmp_path):
    path = tmp_path / "com.ubuntu.noble.cve.oval.xml"
    path.write_text(SAMPLE_OVAL, encoding="utf-8")
    return path


def test_parse_oval(oval_file):
    rows = {(cve, fixed) for cve, _, _, source, binaries, fixed in parse_oval(oval_file)
            if source == "openssh" and binaries == ["openssh-client", "openssh-server"]}
    assert rows == {("CVE-2024-6387", "1:9.6p1-3ubuntu13.3"), ("CVE-2026-1", None), ("CVE-2026-2", "1:9.6p1-3ubuntu13.99~esm1")}


def test_distro_status():
    index = {
        ("CVE-2024-6387", "openssh-server"): ("1:9.6p1-3ubuntu13.3", "USN-6859-1"),
        ("CVE-2026-1", "openssh-server"): (None, None),
        ("CVE-2026-2", "openssh-server"): ("1:9.6p1-3ubuntu13.99~esm1", "USN-9000-1"),
    }
    installed = "1:9.6p1-3ubuntu13.19"
    assert distro_status(index, ["CVE-2024-6387"], ["openssh-server"], installed)["status"] == "fixed"
    assert distro_status(index, ["CVE-2024-6387"], ["openssh-server"], "1:9.6p1-3ubuntu13.2")["status"] == "vulnerable"
    assert distro_status(index, ["CVE-2026-1"], ["openssh-server"], installed)["status"] == "unfixed"
    pro = distro_status(index, ["CVE-2026-2"], ["openssh-server"], installed)
    assert (pro["status"], pro["fix_requires_pro"], pro["usns"]) == ("vulnerable", True, ["USN-9000-1"])
    assert distro_status(index, ["CVE-2030-1"], ["openssh-server"], installed)["status"] == "unknown"
    # несколько CVE: самое тяжёлое состояние определяет находку
    assert distro_status(index, ["CVE-2024-6387", "CVE-2026-1"], ["openssh-server"], installed)["status"] == "unfixed"


def test_api_applies_ubuntu_status(client, db, bdu_loaded, org_with_host, oval_file):
    db.execute(text("UPDATE assets SET os = 'Ubuntu 24.04.4 LTS' WHERE id = :a"), {"a": org_with_host["asset_id"]})
    db.commit()
    stats = import_oval(db, "noble", oval_file)
    assert (stats.cves, stats.rows) == (3, 6)

    body = client.get(f"/api/organizations/{org_with_host['id']}/vulnerabilities", headers=org_with_host["headers"]).json()

    # CVE-2024-6387 исправлен в 13.3, установлена 13.19 — уязвимости на хосте нет, в счёт не входит.
    (item,) = body["items"]
    assert item["distro"]["status"] == "fixed" and item["distro"]["fixed_version"] == "1:9.6p1-3ubuntu13.3"
    assert body["total"] == 0 and body["summary"]["medium"] == 0
    assert body["distro_summary"]["fixed"] == 1 and body["oval"][0]["release"] == "noble"


def test_api_without_oval_leaves_findings_potential(client, bdu_loaded, org_with_host):
    body = client.get(f"/api/organizations/{org_with_host['id']}/vulnerabilities", headers=org_with_host["headers"]).json()
    assert body["items"][0]["distro"] is None and body["distro_summary"]["not_checked"] == 1


# ---------- хранимые находки: формула V в SQL, пересчёт, страницы ----------

PARITY_XML_TEMPLATE = """ <vul><identifier>BDU:2030-{n:05d}</identifier>
  <name>{name}</name>
  <vulnerable_software><soft><name>OpenSSH</name><vendor>OpenBSD</vendor><version>от 1.0 до 99.0</version></soft></vulnerable_software>
  {cvss}<exploit_status>{exploit}</exploit_status><vul_incident>{incident}</vul_incident>
 </vul>
"""


def _org_with_assets(db, make_org, specs):
    """specs: [(hostname, asset_type, platform_tags, os)] — у каждого актива openssh 9.6p1."""
    org_id = make_org(f"Parity {uuid.uuid4().hex[:6]}")
    env_id = str(uuid.uuid4())
    db.execute(text("INSERT INTO environments (id, organization_id, name) VALUES (:e, :o, 'prod')"), {"e": env_id, "o": org_id})
    ids = []
    for hostname, asset_type, tags, os_name in specs:
        aid = str(uuid.uuid4())
        db.execute(text("INSERT INTO assets (id, environment_id, hostname, asset_type, platform_tags, os) "
                        "VALUES (:a, :e, :h, :t, CAST(:p AS jsonb), :os)"),
                   {"a": aid, "e": env_id, "h": hostname, "t": asset_type, "p": json.dumps(tags), "os": os_name})
        db.execute(text("INSERT INTO software (asset_id, name, version) VALUES (:a, 'openssh-server', '1:9.6p1-3ubuntu13.19')"),
                   {"a": aid})
        ids.append(aid)
    db.commit()
    return org_id, ids


def test_sql_formula_matches_python_criticality_for_every_combination(db, tmp_path, make_org):
    """V и уровень на странице считает SQL (страницы и сводка на тысячах находок) — ровно как criticality()."""
    names = ["Уязвимость, позволяющая выполнить произвольный код", "Уязвимость, позволяющая вызвать отказ в обслуживании",
             "Уязвимость, позволяющая раскрыть защищаемую информацию", "Уязвимость без понятных последствий",
             "Межсайтовый скриптинг", "Уязвимость, позволяющая повысить свои привилегии"]
    cvss_variants = ['<cvss3><vector score="{s}">AV:N</vector></cvss3>', '<cvss><vector score="{s}">AV:N</vector></cvss>', ""]
    scores = ["9,8", "8,1", "7,5", "5,3", "4,3", "2,1", "0,1", "10"]
    exploits = [("Существует", "Нет"), ("Существует в открытом доступе", "Да"), ("Данные уточняются", "")]
    rows, n = [], 0
    for name in names:
        for cv in cvss_variants:
            for score in scores:
                for exploit, incident in exploits:
                    n += 1
                    rows.append(PARITY_XML_TEMPLATE.format(n=n, name=name, cvss=cv.format(s=score), exploit=exploit, incident=incident))
    archive = tmp_path / "parity.xml"
    archive.write_text('<?xml version="1.0" encoding="UTF-8"?><vulnerabilities>' + "".join(rows) + "</vulnerabilities>", encoding="utf-8")
    import_bdu(db, archive)

    # 7 активов разных типов, у части — доступ из интернета; доли поражённых активов — разные пороги L
    specs = [("srv-a", "linux-server", [], "Ubuntu 22.04"), ("srv-b", "network-device", ["internet-facing"], "Cisco IOS"),
             ("srv-c", "windows-client", [], "Windows 11"), ("srv-d", "storage", ["internet-facing"], None),
             ("srv-e", "unknown-kind", [], None), ("srv-f", None, [], None), ("srv-g", "firewall", [], None)]
    org_id, _ = _org_with_assets(db, make_org, specs)
    body = organization_vulnerabilities(db, org_id, limit=500)
    total_assets = len(specs)
    bdu = {r.bdu_id: r for r in db.execute(text("SELECT * FROM bdu_vulnerabilities")).all()}
    by_host = {h: (t, tags) for h, t, tags, _ in specs}
    checked = 0
    for start in range(0, body["found"], 500):
        page = organization_vulnerabilities(db, org_id, limit=500, offset=start)
        for item in page["items"]:
            v = bdu[item["bdu_id"]]
            asset_type, tags = by_host[item["asset"]["hostname"]]
            expected = criticality(
                cvss3=float(v.cvss3) if v.cvss3 is not None else None, cvss2=float(v.cvss2) if v.cvss2 is not None else None,
                asset_type=asset_type, affected_assets=total_assets, total_assets=total_assets,
                internet_facing="internet-facing" in tags, exploit_status=v.exploit_status, incident=v.incident, name=v.name,
            )
            if expected is None:
                assert item["criticality"] is None and item["level"] is None
            else:
                assert item["criticality"]["v"] == expected.v and item["level"] == expected.level, (item, expected)
                assert item["criticality"]["iinfr"] == expected.iinfr
            checked += 1
    assert checked == body["found"] == n * total_assets


def test_share_of_affected_assets_changes_level_like_python(db, tmp_path, make_org):
    """L — доля активов организации с уязвимостью: 1 из 20 (0,5), 3 из 20 (0,6), 11 из 20 (0,8), 15 из 20 (1,0)."""
    archive = tmp_path / "one.xml"
    archive.write_text('<?xml version="1.0" encoding="UTF-8"?><vulnerabilities>' + PARITY_XML_TEMPLATE.format(
        n=1, name="Уязвимость, позволяющая выполнить произвольный код", cvss='<cvss3><vector score="8,8">AV:N</vector></cvss3>',
        exploit="Существует", incident="") + "</vulnerabilities>", encoding="utf-8")
    import_bdu(db, archive)
    for affected in (1, 3, 11, 15):
        specs = [(f"h{i}", "linux-server", [], None) for i in range(20)]
        org_id, ids = _org_with_assets(db, make_org, specs)
        db.execute(text("DELETE FROM software WHERE asset_id = ANY(CAST(:ids AS uuid[]))"), {"ids": ids[affected:]})
        db.commit()
        item = organization_vulnerabilities(db, org_id)["items"][0]
        expected = criticality(cvss3=8.8, cvss2=None, asset_type="linux-server", affected_assets=affected, total_assets=20,
                               internet_facing=False, exploit_status="Существует", incident="", name=item["name"])
        assert (item["criticality"]["v"], item["level"]) == (expected.v, expected.level)


def test_findings_are_recomputed_after_new_software_new_bdu_new_oval_and_os_change(client, db, bdu_loaded, org_with_host,
                                                                                   oval_file, tmp_path):
    url, headers = f"/api/organizations/{org_with_host['id']}/vulnerabilities", org_with_host["headers"]
    first = client.get(url, headers=headers).json()
    assert first["found"] == 1 and first["items"][0]["distro"] is None
    computed = db.execute(text("SELECT computed_at FROM asset_vulnerability_state")).scalar()
    # повторное чтение — без пересчёта
    client.get(url, headers=headers)
    assert db.execute(text("SELECT computed_at FROM asset_vulnerability_state")).scalar() == computed

    # данные Ubuntu и ОС актива: статус дистрибутива появляется
    db.execute(text("UPDATE assets SET os = 'Ubuntu 24.04.4 LTS' WHERE id = :a"), {"a": org_with_host["asset_id"]})
    db.commit()
    import_oval(db, "noble", oval_file)
    assert client.get(url, headers=headers).json()["items"][0]["distro"]["status"] == "fixed"

    # новая копия БДУ без этой уязвимости — находки исчезают
    single = tmp_path / "other.xml"
    single.write_text(SAMPLE_XML.replace("BDU:2024-04914", "BDU:2024-00000").replace("от 8.6 до 9.8", "до 1.0"), encoding="utf-8")
    import_bdu(db, single)
    assert client.get(url, headers=headers).json()["found"] == 0


def test_new_agent_report_recomputes_findings_of_its_asset(client, db, bdu_loaded, make_org, make_agent_key, make_user,
                                                          add_membership, auth_header):
    org_id = make_org("Ingest BDU Org")
    key = make_agent_key(org_id)
    add_membership(make_user("ingest-bdu@example.com"), org_id)
    headers = auth_header("ingest-bdu@example.com")

    def report(version):
        payload = {"environment": "prod", "asset": {"hostname": "web-01", "asset_type": "linux-server", "os": "Debian 12"},
                   "software": [{"name": "openssh-server", "version": version}], "facts": {}}
        assert client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": key}).status_code == 200

    report("1:9.6p1-3")
    url = f"/api/organizations/{org_id}/vulnerabilities"
    assert [i["bdu_id"] for i in client.get(url, headers=headers).json()["items"]] == ["BDU:2024-04914"]
    report("1:9.9p1-1")  # обновили OpenSSH — уязвимость больше не подходит
    assert client.get(url, headers=headers).json()["found"] == 0
    report("1:7.2p1-1")  # старая версия — подходит «до 7.4»
    assert [i["bdu_id"] for i in client.get(url, headers=headers).json()["items"]] == ["BDU:2019-00001"]


def test_filters_search_and_pages(db, tmp_path, make_org, client, add_membership, make_user, auth_header):
    rows = "".join(PARITY_XML_TEMPLATE.format(
        n=i, name=f"Уязвимость номер {i}", cvss=f'<cvss3><vector score="{s}">AV:N</vector></cvss3>', exploit="Существует", incident="")
        for i, s in enumerate(["9,8", "7,5", "4,0", "1,0", "6,0"], start=1))
    archive = tmp_path / "f.xml"
    archive.write_text(f'<?xml version="1.0" encoding="UTF-8"?><vulnerabilities>{rows}</vulnerabilities>', encoding="utf-8")
    import_bdu(db, archive)
    org_id, ids = _org_with_assets(db, make_org, [("alpha", "network-device", ["internet-facing"], None), ("beta", "linux-server", [], None)])
    add_membership(make_user("vuln-filter@example.com"), org_id)
    headers = auth_header("vuln-filter@example.com")
    url = f"/api/organizations/{org_id}/vulnerabilities"

    def get(**params):
        resp = client.get(url, params=params, headers=headers)
        assert resp.status_code == 200, resp.text
        return resp.json()

    full = get()
    assert full["found"] == full["total"] == 10
    levels = [i["level"] for i in full["items"]]
    assert levels == sorted(levels, key=lambda lvl: LEVEL_ORDER[lvl])  # сначала самые критичные
    for level in ("critical", "high", "medium", "low"):
        assert get(level=level)["found"] == full["summary"][level]
    assert get(q="alpha")["found"] == 5 and get(q="2030-00003")["found"] == 2 and get(q="%")["found"] == 0
    assert get(asset_id=ids[1])["found"] == 5 and get(asset_id=ids[1])["summary"] != full["summary"]
    pages = [get(limit=3, offset=o)["items"] for o in (0, 3, 6, 9)]
    keys = [(i["bdu_id"], i["asset"]["hostname"]) for p in pages for i in p]
    assert len(keys) == len(set(keys)) == 10
    assert get(distro="not_checked")["found"] == 10 and get(distro="fixed")["found"] == 0
    for bad in ({"level": "urgent"}, {"distro": "x"}, {"limit": 501}):
        assert client.get(url, params=bad, headers=headers).status_code == 422


def test_vulnerability_listing_two_installed_products_is_one_finding(db, tmp_path, make_org):
    archive = tmp_path / "two.xml"
    archive.write_text("""<?xml version="1.0" encoding="UTF-8"?><vulnerabilities>
     <vul><identifier>BDU:2030-99999</identifier><name>Уязвимость OpenSSH и OpenSSL</name>
      <vulnerable_software>
       <soft><name>OpenSSH</name><vendor>OpenBSD</vendor><version>от 1.0 до 99.0</version></soft>
       <soft><name>OpenSSL</name><vendor>OpenSSL</vendor><version>от 1.0 до 99.0</version></soft>
      </vulnerable_software><cvss3><vector score="7,5">AV:N</vector></cvss3>
     </vul></vulnerabilities>""", encoding="utf-8")
    import_bdu(db, archive)
    org_id, ids = _org_with_assets(db, make_org, [("both", "linux-server", [], None)])
    db.execute(text("INSERT INTO software (asset_id, name, version) VALUES (:a, 'openssl', '3.0.13-0ubuntu3')"), {"a": ids[0]})
    db.commit()
    body = organization_vulnerabilities(db, org_id)
    assert body["found"] == 1 and body["items"][0]["product"] == "openssh"


def test_fewer_assets_in_organization_rescore_share_without_new_reports(db, tmp_path, make_org):
    archive = tmp_path / "one.xml"
    archive.write_text('<?xml version="1.0" encoding="UTF-8"?><vulnerabilities>' + PARITY_XML_TEMPLATE.format(
        n=1, name="Уязвимость, позволяющая выполнить произвольный код", cvss='<cvss3><vector score="8,8">AV:N</vector></cvss3>',
        exploit="Существует", incident="") + "</vulnerabilities>", encoding="utf-8")
    import_bdu(db, archive)
    org_id, ids = _org_with_assets(db, make_org, [(f"h{i}", "linux-server", [], None) for i in range(20)])
    db.execute(text("DELETE FROM software WHERE asset_id = ANY(CAST(:ids AS uuid[]))"), {"ids": ids[3:]})
    db.commit()

    def v_for(affected, total):
        return criticality(cvss3=8.8, cvss2=None, asset_type="linux-server", affected_assets=affected, total_assets=total,
                           internet_facing=False, exploit_status="Существует", incident="",
                           name="Уязвимость, позволяющая выполнить произвольный код").v

    assert organization_vulnerabilities(db, org_id)["items"][0]["criticality"]["v"] == v_for(3, 20)  # 15 % → L = 0,6
    db.execute(text("DELETE FROM assets WHERE id = ANY(CAST(:ids AS uuid[]))"), {"ids": ids[6:]})  # осталось 6
    db.commit()
    assert organization_vulnerabilities(db, org_id)["items"][0]["criticality"]["v"] == v_for(3, 6)   # 50 % → L = 0,8
    assert v_for(3, 6) != v_for(3, 20)
