import pytest
from pr2.cipher import (
    KeyType,
    TrithemiusKey,
    TrithemiusCipher,
    BinaryTrithemiusCipher,
    TrithemiusKnownPlaintextAttack,
    BinaryTrithemiusAttack,
)


def test_trithemius_key_parsing_and_validation():
    k_lin = TrithemiusKey.from_any((2, 5))
    assert k_lin.key_type == KeyType.LINEAR
    assert k_lin.linear_coeffs == (2, 5)
    assert TrithemiusKey.validate((2, 5)) is True
    assert TrithemiusKey.validate([3, -1]) is True
    assert TrithemiusKey.validate("2, 5") is True

    k_nl = TrithemiusKey.from_any((1, 2, 3))
    assert k_nl.key_type == KeyType.NON_LINEAR
    assert k_nl.nonlinear_coeffs == (1, 2, 3)
    assert TrithemiusKey.validate((1, 2, 3)) is True
    assert TrithemiusKey.validate([1, -4, 7]) is True
    assert TrithemiusKey.validate("1, 2, 3") is True

    k_motto = TrithemiusKey.from_any("СЕКРЕТ")
    assert k_motto.key_type == KeyType.MOTTO
    assert k_motto.motto == "СЕКРЕТ"
    assert TrithemiusKey.validate("СЕКРЕТ") is True

    assert TrithemiusKey.validate(None) is False
    assert TrithemiusKey.validate(True) is False
    assert TrithemiusKey.validate(False) is False
    assert TrithemiusKey.validate("") is False
    assert TrithemiusKey.validate("   ") is False
    assert TrithemiusKey.validate([1]) is False
    assert TrithemiusKey.validate([1, 2, 3, 4]) is False


def test_trithemius_linear_workflow_ukrainian():
    cipher = TrithemiusCipher()
    original = "Безпека програмного забезпечення! ТВ-31 Гогуля Максим."
    key = (2, 3)

    encrypted = cipher.encrypt(original, key, lang="uk")
    assert encrypted != original
    assert "!" in encrypted
    assert "ТВ-31" in encrypted or "31" in encrypted

    decrypted = cipher.decrypt(encrypted, key, lang="uk")
    assert decrypted == original


def test_trithemius_nonlinear_workflow_ukrainian():
    cipher = TrithemiusCipher()
    original = "Криптосистема Тритеміуса на основі нелінійного закону."
    key = (1, 2, 5)

    encrypted = cipher.encrypt(original, key, lang="uk")
    assert encrypted != original

    decrypted = cipher.decrypt(encrypted, key, lang="uk")
    assert decrypted == original


def test_trithemius_motto_workflow_ukrainian():
    cipher = TrithemiusCipher()
    original = "Слава Україні! Героям Слава! Комп'ютерний практикум."
    key = "КИЇВ"

    encrypted = cipher.encrypt(original, key, lang="uk")
    assert encrypted != original

    decrypted = cipher.decrypt(encrypted, key, lang="uk")
    assert decrypted == original


def test_trithemius_linear_workflow_english():
    cipher = TrithemiusCipher()
    original = "Trithemius Polyalphabetic Substitution Cipher in Python 3.13!"
    key = (3, 7)

    encrypted = cipher.encrypt(original, key, lang="en")
    assert encrypted != original
    assert "3.13!" in encrypted

    decrypted = cipher.decrypt(encrypted, key, lang="en")
    assert decrypted == original


def test_trithemius_motto_workflow_english():
    cipher = TrithemiusCipher()
    original = "Polyalphabetic substitution using secret keyword."
    key = "CIPHER"

    encrypted = cipher.encrypt(original, key, lang="en")
    assert encrypted != original

    decrypted = cipher.decrypt(encrypted, key, lang="en")
    assert decrypted == original


def test_trithemius_key_validation_errors():
    cipher = TrithemiusCipher()

    with pytest.raises(TypeError):
        cipher.encrypt(12345, (1, 2))  # type: ignore

    with pytest.raises(ValueError):
        cipher.encrypt("Тестовий текст", [1, 2, 3, 4, 5])

    with pytest.raises(ValueError):
        cipher.encrypt("Тестовий текст", None)


def test_binary_trithemius_workflow():
    bin_cipher = BinaryTrithemiusCipher()
    raw_data = b"Sample Binary Data \x00\x01\x80\xff with PNG/PDF headers and raw bytes."

    enc_lin = bin_cipher.encrypt(raw_data, (5, 17))
    assert enc_lin != raw_data
    assert len(enc_lin) == len(raw_data)
    dec_lin = bin_cipher.decrypt(enc_lin, (5, 17))
    assert dec_lin == raw_data

    enc_nl = bin_cipher.encrypt(raw_data, (2, 3, 11))
    assert enc_nl != raw_data
    dec_nl = bin_cipher.decrypt(enc_nl, (2, 3, 11))
    assert dec_nl == raw_data

    enc_motto = bin_cipher.encrypt(raw_data, "SECRET_KEY")
    assert enc_motto != raw_data
    dec_motto = bin_cipher.decrypt(enc_motto, "SECRET_KEY")
    assert dec_motto == raw_data


def test_known_plaintext_attack_linear():
    cipher = TrithemiusCipher()
    attack = TrithemiusKnownPlaintextAttack(cipher)

    plaintext = "Шифр Тритеміуса базується на змінному зсуві кожного символу"
    key = (3, 7)
    ciphertext = cipher.encrypt(plaintext, key, lang="uk")

    result = attack.attack(plaintext, ciphertext, lang="uk")
    assert result.success is True
    assert result.primary_candidate is not None
    assert result.primary_candidate.key_type == KeyType.LINEAR
    assert result.primary_candidate.key.linear_coeffs == (3, 7)
    assert result.primary_candidate.verified is True


def test_known_plaintext_attack_nonlinear():
    cipher = TrithemiusCipher()
    attack = TrithemiusKnownPlaintextAttack(cipher)

    plaintext = "Нелінійний закон зміщення значно ускладнює класичний криптоаналіз"
    key = (2, 5, 9)
    ciphertext = cipher.encrypt(plaintext, key, lang="uk")

    result = attack.attack(plaintext, ciphertext, lang="uk")
    assert result.success is True
    assert result.primary_candidate is not None
    assert result.primary_candidate.key_type == KeyType.NON_LINEAR
    assert result.primary_candidate.key.nonlinear_coeffs == (2, 5, 9)
    assert result.primary_candidate.verified is True


def test_known_plaintext_attack_motto():
    cipher = TrithemiusCipher()
    attack = TrithemiusKnownPlaintextAttack(cipher)

    plaintext = "Гасло повторюється під текстом повідомлення кілька разів поспіль для шифрування"
    key = "КИЇВ"
    ciphertext = cipher.encrypt(plaintext, key, lang="uk")

    result = attack.attack(plaintext, ciphertext, lang="uk")
    assert result.success is True
    assert result.primary_candidate is not None
    assert result.primary_candidate.verified is True

    motto_cand = [c for c in result.all_candidates if c.key_type == KeyType.MOTTO]
    assert len(motto_cand) > 0
    assert motto_cand[0].key.motto.lower() == "київ"


def test_binary_known_plaintext_attack():
    bin_cipher = BinaryTrithemiusCipher()
    bin_attack = BinaryTrithemiusAttack()

    raw_data = b"Testing binary active attack on Trithemius cipher with mod 256 arithmetic."
    key = (7, 42)
    enc = bin_cipher.encrypt(raw_data, key)

    recovered_key = bin_attack.attack(raw_data, enc)
    assert recovered_key is not None
    assert recovered_key.key_type == KeyType.LINEAR
    assert recovered_key.linear_coeffs == (7, 42)
