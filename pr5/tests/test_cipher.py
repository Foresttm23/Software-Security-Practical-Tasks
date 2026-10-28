import pytest

from pr5.cipher import (
    AESCipher,
    DESCipher,
    SymmetricCipherError,
    TripleDESCipher,
    create_cipher,
    decode_input,
    encode_output,
    parse_hex,
    text_to_bytes,
)

KEY = b"ABCDEFGH"
IV = b"ABCDEFGH"


def test_des_known_answer_vector():
    des = DESCipher("ECB", "None")
    key = bytes.fromhex("0E329232EA6D0D73")
    assert des.encrypt_bytes(bytes.fromhex("8787878787878787"), key) == bytes(8)


def test_aes_fips197_vector():
    aes = AESCipher("ECB", "None")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert aes.encrypt_bytes(plain, bytes(range(16))).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


@pytest.mark.parametrize("mode", ["CBC", "ECB", "CFB"])
@pytest.mark.parametrize("padding", ["PKCS7", "ANSIX923", "ISO10126", "Zeros"])
def test_des_roundtrip_all_supported_modes(mode, padding):
    des = DESCipher(mode, padding)
    msg = "Hello World! Привіт, ТВ-31"
    assert des.decrypt(des.encrypt(msg, KEY, IV), KEY, IV) == msg


def test_modes_produce_different_ciphertexts():
    msg = "Безпека інформаційних систем"
    results = {mode: DESCipher(mode).encrypt(msg, KEY, IV) for mode in ("CBC", "ECB", "CFB")}
    assert len(set(results.values())) == 3


def test_ecb_leaks_repeated_blocks_but_cbc_does_not():
    data = b"SAMEBLK!" * 2
    ecb = DESCipher("ECB", "None").encrypt_bytes(data, KEY)
    cbc = DESCipher("CBC", "None").encrypt_bytes(data, KEY, IV)
    assert ecb[:8] == ecb[8:16]
    assert cbc[:8] != cbc[8:16]


@pytest.mark.parametrize("mode", ["OFB", "CTS"])
def test_unsupported_net_modes_are_rejected(mode):
    with pytest.raises(SymmetricCipherError, match="не підтримується"):
        DESCipher(mode).encrypt("text", KEY, IV)


@pytest.mark.parametrize("name, key, block", [
    ("DES", b"12345678", 8),
    ("TripleDES", b"0123456789ABCDEF", 8),
    ("TripleDES", b"0123456789ABCDEFGHIJKLMN", 8),
    ("AES", b"K" * 15 + b"1", 16),
    ("AES", bytes(range(32)), 16),
], ids=["DES", "TripleDES-128", "TripleDES-192", "AES-128", "AES-256"])
def test_factory_dynamic_cipher_choice(name, key, block):
    cipher = create_cipher(name, "CBC")
    iv = cipher.generate_iv()
    assert cipher.NAME == name and cipher.block_size == block == len(iv)
    assert cipher.decrypt(cipher.encrypt("Dynamic choice", key, iv), key, iv) == "Dynamic choice"


def test_factory_rejects_unknown_names():
    with pytest.raises(SymmetricCipherError):
        create_cipher("RC2")
    with pytest.raises(SymmetricCipherError):
        create_cipher("DES", mode="CTR")
    with pytest.raises(SymmetricCipherError):
        create_cipher("DES", padding="Random")


@pytest.mark.parametrize("cipher, key, message", [
    (DESCipher(), b"1234567", "8 байт"),
    (AESCipher(), b"x" * 20, "16 / 24 / 32"),
    (DESCipher(), bytes.fromhex("0101010101010101"), "слабким"),
    (DESCipher(), bytes.fromhex("01FE01FE01FE01FE"), "напівслабким"),
    (TripleDESCipher(), b"ABCDEFGHABCDEFGH", "вироджується"),
], ids=["des-short", "aes-20-bytes", "des-weak", "des-semi-weak", "3des-degenerate"])
def test_invalid_and_weak_keys(cipher, key, message):
    assert not cipher.validate_key(key)
    with pytest.raises(SymmetricCipherError, match=message):
        cipher.encrypt("data", key, IV)


def test_iv_validation():
    des = DESCipher("CBC")
    with pytest.raises(SymmetricCipherError, match="потребує"):
        des.encrypt("data", KEY)
    with pytest.raises(SymmetricCipherError, match="8 байт"):
        des.encrypt("data", KEY, b"short")
    with pytest.raises(TypeError):
        des.encrypt("data", KEY, "ABCDEFGH")
    assert DESCipher("ECB").decrypt(DESCipher("ECB").encrypt("no iv", KEY), KEY) == "no iv"


def test_wrong_key_or_damaged_ciphertext_is_detected():
    des = DESCipher()
    ct = des.encrypt("Secret message", KEY, IV)
    with pytest.raises(SymmetricCipherError, match="Не вдалося розшифрувати|UTF-8"):
        des.decrypt(ct, b"HGFEDCBA", IV)
    with pytest.raises(SymmetricCipherError, match="кратна 8"):
        des.decrypt(ct[:-1], KEY, IV)
    with pytest.raises(SymmetricCipherError, match="порожній"):
        des.decrypt(b"", KEY, IV)


def test_data_validation():
    des = DESCipher(padding="None")
    with pytest.raises(SymmetricCipherError, match="кратна 8"):
        des.encrypt("12345", KEY, IV)
    with pytest.raises(SymmetricCipherError, match="Немає даних"):
        DESCipher().encrypt("", KEY, IV)
    with pytest.raises(TypeError):
        DESCipher().encrypt(12345, KEY, IV)
    with pytest.raises(SymmetricCipherError, match="сурогати"):
        DESCipher().encrypt("bad \ud800", KEY, IV)


def test_key_and_text_formats():
    assert text_to_bytes("ABCDEFGH") == KEY
    assert text_to_bytes("41-42 43:44 45464748", "HEX") == KEY
    with pytest.raises(SymmetricCipherError, match="латиницю"):
        text_to_bytes("Ключ1234")
    with pytest.raises(SymmetricCipherError, match="непарну"):
        parse_hex("ABC")
    with pytest.raises(SymmetricCipherError, match="HEX-цифрами"):
        parse_hex("GG")
    data = bytes(range(20))
    for fmt in ("Base64", "HEX"):
        assert decode_input(encode_output(data, fmt), fmt) == data
    with pytest.raises(SymmetricCipherError, match="Base64"):
        decode_input("abc$", "Base64")


def test_embedded_iv_split():
    des = DESCipher()
    iv = des.generate_iv()
    blob = iv + des.encrypt("with iv", KEY, iv)
    got_iv, ct = des.split_iv(blob)
    assert got_iv == iv and des.decrypt(ct, KEY, got_iv) == "with iv"
    with pytest.raises(SymmetricCipherError, match="закороткий"):
        des.split_iv(iv)


def test_generated_keys_are_valid():
    for cipher in (DESCipher(), TripleDESCipher(), AESCipher()):
        key = cipher.generate_key()
        assert cipher.validate_key(key)


def test_file_roundtrip_through_crypto_stream(tmp_path):
    src = tmp_path / "plain.bin"
    src.write_bytes(bytes(range(256)) * 50)
    enc, dec = tmp_path / "enc.bin", tmp_path / "dec.bin"
    aes = AESCipher("CBC")
    key, iv = aes.generate_key(), aes.generate_iv()
    aes.encrypt_file(str(src), str(enc), key, iv, embed_iv=True)
    assert enc.read_bytes()[:16] == iv
    aes.decrypt_file(str(enc), str(dec), key, embed_iv=True)
    assert dec.read_bytes() == src.read_bytes()


def test_file_errors_leave_no_output(tmp_path):
    src = tmp_path / "plain.txt"
    src.write_bytes(b"Hello World!")
    enc, dec = tmp_path / "enc.bin", tmp_path / "dec.bin"
    des = DESCipher()
    des.encrypt_file(str(src), str(enc), KEY, IV)
    with pytest.raises(SymmetricCipherError):
        des.decrypt_file(str(enc), str(dec), b"HGFEDCBA", IV)
    assert not dec.exists() and len(list(tmp_path.iterdir())) == 2
    with pytest.raises(SymmetricCipherError, match="збігатися"):
        des.encrypt_file(str(src), str(src), KEY, IV)
    (tmp_path / "empty.txt").write_bytes(b"")
    with pytest.raises(SymmetricCipherError, match="порожній"):
        des.encrypt_file(str(tmp_path / "empty.txt"), str(dec), KEY, IV)
    with pytest.raises(SymmetricCipherError, match="не знайдено"):
        des.encrypt_file(str(tmp_path / "missing.txt"), str(dec), KEY, IV)
