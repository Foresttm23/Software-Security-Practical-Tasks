import pytest

from pr7.cipher import (
    WIKI_C,
    WIKI_D,
    WIKI_E,
    WIKI_M,
    WIKI_P,
    WIKI_Q,
    NetRSACipher,
    RSAError,
    RSAFactorAttack,
    TextbookRSA,
    is_probable_prime,
    parse_numbers,
)

rsa = TextbookRSA()
WIKI_KEY = TextbookRSA.make_key(WIKI_P, WIKI_Q, WIKI_E)


@pytest.fixture(scope="module")
def net():
    return NetRSACipher(1024)


def test_wikipedia_example_key():
    assert (WIKI_KEY.n, WIKI_KEY.phi, WIKI_KEY.d) == (3233, 3120, WIKI_D)


def test_wikipedia_example_encrypt_decrypt():
    assert rsa.encrypt_int(WIKI_M, WIKI_KEY) == WIKI_C
    assert rsa.decrypt_int(WIKI_C, WIKI_KEY) == WIKI_M


@pytest.mark.parametrize("p, q, e", [
    (61, 61, 17),      # p = q
    (60, 53, 17),      # p не просте
    (61, 53, 3120),    # e >= φ
    (61, 53, 15),      # НСД(e, φ) = 3
    (61, "abc", 17),   # не число
])
def test_invalid_key_parameters_rejected(p, q, e):
    with pytest.raises(RSAError):
        TextbookRSA.make_key(p, q, e)


def test_message_must_be_less_than_modulus():
    with pytest.raises(RSAError, match="менше модуля"):
        rsa.encrypt_int(3233, WIKI_KEY)


def test_decrypt_requires_private_key():
    with pytest.raises(RSAError, match="закритий ключ"):
        rsa.decrypt_int(WIKI_C, WIKI_KEY.public())


def test_text_roundtrip_with_generated_key():
    key = TextbookRSA.generate_key(128)
    assert key.bits == 128 and is_probable_prime(key.p) and is_probable_prime(key.q)
    msg = "Привіт, RSA! ТВ-31"
    assert rsa.decrypt_text(rsa.encrypt_text(msg, key), key) == msg


def test_parse_numbers_rejects_garbage():
    assert parse_numbers("2790, 65; 1") == [2790, 65, 1]
    with pytest.raises(RSAError):
        parse_numbers("12 x7")
    with pytest.raises(RSAError):
        parse_numbers("   ")


@pytest.mark.parametrize("padding", ["OAEP", "PKCS1"])
def test_net_roundtrip(net, padding):
    msg = "Hello World! Безпека інформаційних систем"
    assert net.decrypt_text(net.encrypt_text(msg, padding), padding) == msg


def test_net_encrypt_with_imported_public_key(net):
    sender = NetRSACipher(None, net.export_xml(False))
    assert not sender.has_private
    cipher_text = sender.encrypt_text("Data to encrypt")
    assert net.decrypt_text(cipher_text) == "Data to encrypt"
    with pytest.raises(RSAError, match="закритий ключ"):
        sender.decrypt_text(cipher_text)


def test_net_wrong_private_key_fails(net):
    cipher_text = net.encrypt_text("secret")
    with pytest.raises(RSAError, match="Не вдалося розшифрувати"):
        NetRSACipher(1024).decrypt_text(cipher_text)


def test_net_message_too_long(net):
    limit = net.max_message_size("OAEP")
    assert limit == 1024 // 8 - 42
    with pytest.raises(RSAError, match="завелике"):
        net.encrypt_bytes(b"A" * (limit + 1))


@pytest.mark.parametrize("xml", ["", "<a/>", "<RSAKeyValue><Modulus>@@</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"],
                         ids=["empty", "not-rsa", "bad-base64"])
def test_net_invalid_xml_rejected(xml):
    with pytest.raises(RSAError):
        NetRSACipher(None, xml)


def test_net_invalid_key_size():
    with pytest.raises(RSAError, match="кроком"):
        NetRSACipher(1025)


def test_attack_recovers_private_key_and_message():
    key = TextbookRSA.generate_key(64)
    cipher_blocks = rsa.encrypt_text("RSA attack", key)
    result = RSAFactorAttack().attack(key.n, key.e)
    assert {result.key.p, result.key.q} == {key.p, key.q}
    assert result.key.d == key.d
    assert rsa.decrypt_text(cipher_blocks, result.key) == "RSA attack"


@pytest.mark.parametrize("n, match", [(3229, "простим"), (3721, "квадрат")], ids=["prime", "square"])
def test_attack_rejects_non_rsa_modulus(n, match):
    with pytest.raises(RSAError, match=match):
        RSAFactorAttack().factorize(n)
