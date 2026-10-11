"""Проверка подписи паков Ed25519 на чистом Python: тестовые векторы RFC 8032 (7.1), подделки, схема выбора."""
import base64

import pytest

import probes
from probes import ManifestError, canonical_json, ed25519_verify, load_verified_manifests

# RFC 8032, 7.1, TEST 1 и TEST 2 (сверены с библиотекой cryptography)
VECTORS = [
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


@pytest.mark.parametrize("public,message,signature", VECTORS)
def test_rfc8032_vectors(public, message, signature):
    pub, msg, sig = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
    assert ed25519_verify(pub, msg, sig)
    assert not ed25519_verify(pub, msg + b"x", sig)                         # другое сообщение
    assert not ed25519_verify(pub, msg, sig[:63] + bytes([sig[63] ^ 1]))    # испорченная подпись
    assert not ed25519_verify(bytes.fromhex(VECTORS[1 - VECTORS.index((public, message, signature))][0]), msg, sig)  # чужой ключ


def test_malformed_inputs_are_rejected_not_crashing():
    pub, _, sig = (bytes.fromhex(v) for v in VECTORS[0])
    assert not ed25519_verify(pub[:31], b"", sig)
    assert not ed25519_verify(pub, b"", sig[:63])
    big_s = sig[:32] + (2 ** 255 - 1).to_bytes(32, "little")                 # s >= L — неканоническая
    assert not ed25519_verify(pub, b"", big_s)
    assert not ed25519_verify(b"\xff" * 32, b"", sig)                        # не точка кривой


def test_public_key_formats():
    hex_key = VECTORS[0][0]
    assert probes.decode_public_key(hex_key) == bytes.fromhex(hex_key)
    assert probes.decode_public_key(base64.b64encode(bytes.fromhex(hex_key)).decode()) == bytes.fromhex(hex_key)
    with pytest.raises(ManifestError):
        probes.decode_public_key("short")


MANIFEST = {"schema": probes.MANIFEST_SCHEMA, "pack": "p", "version": "1.0.0", "detect": [], "checks": []}


def test_with_public_key_hmac_signature_is_not_accepted():
    """Агент с открытым ключом не принимает HMAC-подпись: иначе укравший общий ключ обошёл бы Ed25519."""
    import hashlib
    import hmac

    hmac_sig = hmac.new(b"shared", canonical_json(MANIFEST), hashlib.sha256).hexdigest()
    response = {"manifests": [{"manifest": MANIFEST, "signature": hmac_sig}]}
    assert load_verified_manifests(response, "shared") == [MANIFEST]
    with pytest.raises(ManifestError, match="неверна"):
        load_verified_manifests(response, "shared", bytes.fromhex(VECTORS[0][0]))


def test_no_verification_key_at_all_is_an_error():
    with pytest.raises(ManifestError, match="нет ключа"):
        load_verified_manifests({"manifests": []})
