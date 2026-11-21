import pytest

from pr8.cipher import (
    DSA_EXAMPLE_PUBLIC_XML,
    DSA_EXAMPLE_SIGNATURE_B64,
    EXAMPLE_MESSAGE,
    RSA_EXAMPLE_SIGNATURE_B64,
    RSA_EXAMPLE_SIGNATURE_HEX,
    RSA_EXAMPLE_XML,
    NetDSASigner,
    NetRSASigner,
    SignatureError,
    compute_hash,
    decode_signature,
)

MESSAGE = "Безпека інформаційних систем, ТВ-31"


@pytest.fixture(scope="module")
def rsa():
    return NetRSASigner(1024)


@pytest.fixture(scope="module")
def dsa():
    return NetDSASigner(1024)


def test_sha1_digest_of_example():
    assert compute_hash(EXAMPLE_MESSAGE.encode()).hex().upper() == "D3486AE9136E7856BC42212385EA797094475802"


@pytest.mark.parametrize("signature, fmt", [
    (RSA_EXAMPLE_SIGNATURE_HEX, "HEX"),
    (RSA_EXAMPLE_SIGNATURE_B64, "Base64"),
], ids=["hex", "base64"])
def test_rsa_example_verifies_with_public_key(signature, fmt):
    public = NetRSASigner(None, RSA_EXAMPLE_XML).public_signer()
    assert not public.has_private
    assert public.verify_text(EXAMPLE_MESSAGE, signature, fmt)


def test_rsa_example_signature_is_reproduced():
    signer = NetRSASigner(None, RSA_EXAMPLE_XML)
    assert signer.sign_text(EXAMPLE_MESSAGE, "HEX") == RSA_EXAMPLE_SIGNATURE_HEX
    assert signer.sign_text(EXAMPLE_MESSAGE, "Base64") == RSA_EXAMPLE_SIGNATURE_B64


def test_dsa_example_verifies():
    verifier = NetDSASigner(None, DSA_EXAMPLE_PUBLIC_XML)
    assert verifier.verify_text(EXAMPLE_MESSAGE, DSA_EXAMPLE_SIGNATURE_B64, "Base64")
    assert not verifier.verify_text("Hello world?", DSA_EXAMPLE_SIGNATURE_B64, "Base64")


@pytest.mark.parametrize("algorithm", ["SHA1", "SHA256", "SHA512"])
def test_rsa_sign_and_verify_roundtrip(rsa, algorithm):
    signature = rsa.sign(MESSAGE, algorithm)
    assert len(signature) == 128
    assert rsa.public_signer().verify(MESSAGE, signature, algorithm)


def test_dsa_sign_and_verify_roundtrip(dsa):
    signature = dsa.sign(MESSAGE)
    assert len(signature) == 40
    assert dsa.public_signer().verify(MESSAGE, signature)


@pytest.mark.parametrize("signer_name", ["rsa", "dsa"])
def test_tampered_message_or_signature_fails(signer_name, request):
    signer = request.getfixturevalue(signer_name)
    signature = bytearray(signer.sign(MESSAGE))
    assert not signer.verify(MESSAGE + ".", bytes(signature))
    signature[5] ^= 0x01
    assert not signer.verify(MESSAGE, bytes(signature))


def test_signature_from_other_key_fails(rsa):
    assert not NetRSASigner(1024).verify(MESSAGE, rsa.sign(MESSAGE))


def test_public_key_cannot_sign(rsa):
    with pytest.raises(SignatureError, match="закритий ключ"):
        rsa.public_signer().sign(MESSAGE)


@pytest.mark.parametrize("text, fmt", [
    ("", "HEX"),
    ("ABC", "HEX"),
    ("ZZ11", "HEX"),
    ("not base64!", "Base64"),
], ids=["empty", "odd-hex", "bad-hex", "bad-base64"])
def test_invalid_signature_text(text, fmt):
    with pytest.raises(SignatureError):
        decode_signature(text, fmt)


def test_wrong_signature_length(rsa):
    with pytest.raises(SignatureError, match="Довжина підпису"):
        rsa.verify(MESSAGE, b"\x01" * 64)


def test_key_of_other_algorithm_rejected():
    with pytest.raises(SignatureError, match="ключ RSA"):
        NetDSASigner(None, RSA_EXAMPLE_XML)
    with pytest.raises(SignatureError, match="ключ DSA"):
        NetRSASigner(None, DSA_EXAMPLE_PUBLIC_XML)


@pytest.mark.parametrize("cls, size", [(NetRSASigner, 100), (NetDSASigner, 2048), (NetDSASigner, 600)],
                         ids=["rsa-100", "dsa-2048", "dsa-600"])
def test_illegal_key_size(cls, size):
    with pytest.raises(SignatureError, match="Розмір ключа"):
        cls.check_key_size(size)


@pytest.mark.parametrize("message", ["", "\ud800"], ids=["empty", "lone-surrogate"])
def test_invalid_message(rsa, message):
    with pytest.raises(SignatureError):
        rsa.sign(message)


def test_dsa_supports_only_sha1(dsa):
    with pytest.raises(SignatureError, match="SHA1"):
        dsa.sign(MESSAGE, "SHA256")
