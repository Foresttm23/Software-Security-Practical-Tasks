import pytest
from pr1.cipher import CaesarCipher, BinaryCaesarCipher, CaesarBruteForce


def test_caesar_text_workflow_ukrainian():
    cipher = CaesarCipher()
    original = "Привіт, Світе! 123 (з ґ, є, і, ї)"
    key = 7

    encrypted = cipher.encrypt(original, key, lang="uk")
    assert encrypted != original

    assert "123" in encrypted

    decrypted = cipher.decrypt(encrypted, key, lang="uk")
    assert decrypted == original


def test_caesar_text_workflow_english():
    cipher = CaesarCipher()
    original = "Hello World! Caesar Cipher with key 5."
    key = 5

    encrypted = cipher.encrypt(original, key, lang="en")
    assert encrypted != original
    assert "!" in encrypted

    decrypted = cipher.decrypt(encrypted, key, lang="en")
    assert decrypted == original


def test_caesar_key_validation():
    cipher = CaesarCipher()
    assert cipher.validate_key(3) is True
    assert cipher.validate_key("14") is True
    assert cipher.validate_key("abc") is False
    assert cipher.validate_key(None) is False
    assert cipher.validate_key(True) is False

    with pytest.raises(ValueError):
        cipher.encrypt("Test", "invalid_key")


def test_brute_force_attack():
    cipher = CaesarCipher()
    bf = CaesarBruteForce(cipher)

    original = "Криптографічний захист інформації"
    key = 11
    encrypted = cipher.encrypt(original, key, lang="uk")

    results = bf.attack(encrypted, lang="uk")

    found = [(k, text) for k, text, score in results if k == key]
    assert len(found) == 1
    assert found[0][1] == original

    # Top result should be the original text
    top_result = results[0]
    assert top_result[0] == key
    assert top_result[1] == original


def test_binary_cipher_workflow():
    binary_cipher = BinaryCaesarCipher()
    raw_data = b"Arbitrary binary file content: \x00\x01\xfe\xff with PDF/PNG header"
    key = 42

    encrypted = binary_cipher.encrypt(raw_data, key)
    assert encrypted != raw_data
    assert len(encrypted) == len(raw_data)

    decrypted = binary_cipher.decrypt(encrypted, key)
    assert decrypted == raw_data
