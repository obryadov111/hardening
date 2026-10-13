"""Хеши паролей: bcrypt напрямую, совместимо с хешами, которые раньше делал passlib (они в БД прода)."""
from app.core.security import hash_password, verify_password

# Сделаны passlib 1.7.4 (CryptContext(schemes=["bcrypt"])) до перехода на bcrypt напрямую.
PASSLIB_HASH = "$2b$12$C0Pi7b/dn22vz/CDUgQrY.0CBrM.uMGHp3u1W.EgBPwuJiZAs/kh6"  # «Пароль-для-проверки-1»
PASSLIB_LONG = "$2b$12$pveyJckCmZrgTFm4eU.0KOm3/gBfo89KH1abUsOJ9Qd508JAuq7ti"  # «Я» × 60


def test_hashes_made_by_passlib_still_verify():
    assert verify_password("Пароль-для-проверки-1", PASSLIB_HASH)
    assert not verify_password("Пароль-для-проверки-2", PASSLIB_HASH)
    # passlib учитывал первые 72 байта — так же и сейчас: тот, кто входил с длинным паролем, войдёт
    assert verify_password("Я" * 60, PASSLIB_LONG)
    assert verify_password("Я" * 36 + "Ж" * 24, PASSLIB_LONG)


def test_new_hash_is_salted_bcrypt_and_verifies():
    first, second = hash_password("Correct-horse-1"), hash_password("Correct-horse-1")
    assert first.startswith("$2b$12$") and first != second
    assert verify_password("Correct-horse-1", first) and verify_password("Correct-horse-1", second)
    assert not verify_password("correct-horse-1", first)


def test_garbage_hash_is_a_failed_check_not_an_error():
    for broken in ("", "not-a-hash", "$2b$12$short", "пароль"):
        assert verify_password("anything-123", broken) is False
