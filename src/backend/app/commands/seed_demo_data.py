"""Накатить демо-данные для локальной разработки одной командой:
организация, контур, пара активов, набор проверок харденинга и отчёт.
Идемпотентно — если организация с таким именем уже есть, ничего не делает.

Usage: python -m app.commands.seed_demo_data
"""
import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.asset import Asset
from app.models.environment import Environment
from app.models.hardening import HardeningCheck, HardeningReport, HardeningRule
from app.models.organization import ClientOrganization

DEMO_ORG_NAME = "Demo Corp"

ASSETS = [
    {"hostname": "demo-web-01", "ip_address": "10.10.0.11", "os": "Ubuntu 22.04", "asset_type": "server", "criticality": "critical"},
    {"hostname": "demo-db-01", "ip_address": "10.10.0.12", "os": "Ubuntu 22.04", "asset_type": "server", "criticality": "critical"},
    {"hostname": "demo-app-01", "ip_address": "10.10.0.13", "os": "Ubuntu 22.04", "asset_type": "server", "criticality": "medium"},
]

# rule_code -> (actual_value, status): часть проверок специально "проваленная"
CHECK_RESULTS = {
    "ssh.permit_root_login": ("no", "pass"),
    "ssh.password_authentication": ("yes", "fail"),
    "ssh.permit_empty_passwords": ("no", "pass"),
    "firewall.ufw_enabled": ("false", "fail"),
    "updates.unattended_upgrades_enabled": ("true", "pass"),
    "password_policy.pass_min_len": ("8", "fail"),
}


def main():
    db: Session = SessionLocal()
    try:
        exists = db.query(ClientOrganization).filter(ClientOrganization.name == DEMO_ORG_NAME).first()
        if exists:
            print(f"Организация '{DEMO_ORG_NAME}' уже существует (id={exists.id}) — пропускаю.")
            return

        now = datetime.now(UTC)

        org = ClientOrganization(name=DEMO_ORG_NAME, industry="IT", country="Russia", created_at=now)
        db.add(org)
        db.flush()

        environment = Environment(organization_id=org.id, name="Production")
        db.add(environment)
        db.flush()

        assets = []
        for item in ASSETS:
            asset = Asset(environment_id=environment.id, created_at=now, **item)
            db.add(asset)
            assets.append(asset)
        db.flush()

        rules = db.query(HardeningRule).filter(HardeningRule.rule_code.in_(CHECK_RESULTS.keys())).all()
        rules_by_code = {rule.rule_code: rule for rule in rules}

        total = passed = failed = 0
        for asset in assets:
            for rule_code, (actual_value, status) in CHECK_RESULTS.items():
                rule = rules_by_code.get(rule_code)
                if not rule:
                    continue

                db.add(
                    HardeningCheck(
                        id=uuid.uuid4(),
                        asset_id=asset.id,
                        rule_id=rule.id,
                        actual_value=actual_value,
                        expected_value=rule.expected_value,
                        status=status,
                        checked_at=now,
                    )
                )
                total += 1
                passed += status == "pass"
                failed += status == "fail"

        compliance_score = round((passed / (passed + failed)) * 100, 2) if (passed + failed) else None

        db.add(
            HardeningReport(
                organization_id=org.id,
                total_checks=total,
                passed=passed,
                failed=failed,
                compliance_score=compliance_score,
                generated_at=now,
            )
        )

        db.commit()
        print(f"Готово: организация '{DEMO_ORG_NAME}' (id={org.id}), {len(assets)} активов, {total} проверок.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
