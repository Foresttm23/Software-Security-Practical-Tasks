import pytest

from pr3.cipher import (
    BOOK_SAMPLE,
    NEKRASOV_SHKOLNIK,
    SHEVCHENKO_ZAPOVIT,
    UK_ALPHABET,
    BealeCipher,
    BealeKey,
    OttendorfCipher,
    OttendorfKey,
    PoemCipher,
    PoemKey,
    split_words,
)


def test_manual_example_from_lab_description():
    poem = PoemCipher()
    assert poem.decrypt("4/3, 5/2, 8/6, 2/3, 1/5, 7/7, 10/1, 6 / 2", NEKRASOV_SHKOLNIK) == "СООБШИТЕ"
    assert poem.decrypt("10/9, 1/4, 8/3, 5/5, 1/5, 8/8, 9/9, 6/2", NEKRASOV_SHKOLNIK) == "СООБШИТЕ"


def test_poem_key_grid():
    key = PoemKey("абвгдеёжзийк, ЛМН!\n\n— ... —\nпр", rows=3, cols=10)
    assert key.grid[0] == list("АБВГДЕЁЖЗИ")
    assert key.grid[1] == ["П", "Р"] + [""] * 8
    assert key.grid[2] == [""] * 10
    assert not key.contains("Й")


def test_poem_roundtrip():
    poem = PoemCipher()
    msg = "Мене на могилі серед степу"
    enc = poem.encrypt(msg, SHEVCHENKO_ZAPOVIT)
    assert poem.decrypt(enc, SHEVCHENKO_ZAPOVIT) == msg.upper()


def test_every_code_points_to_the_encrypted_letter():
    poem = PoemCipher()
    key = PoemKey(NEKRASOV_SHKOLNIK)
    msg = "НЕБОЕЛЬНИКИПЕСОК"
    tokens = poem.encrypt(msg, key).split(", ")
    for token, ch in zip(tokens, msg, strict=True):
        assert key.char_at(poem.parse_token(token)) == ch


def test_encryption_is_random_but_seed_is_reproducible():
    poem = PoemCipher()
    msg = "Сообщите товарищу о собрании"
    assert poem.encrypt(msg, NEKRASOV_SHKOLNIK) != poem.encrypt(msg, NEKRASOV_SHKOLNIK)
    assert poem.encrypt(msg, NEKRASOV_SHKOLNIK, seed=7) == poem.encrypt(msg, NEKRASOV_SHKOLNIK, seed=7)


def test_avoid_repeats():
    poem = PoemCipher()
    n = len(PoemKey(NEKRASOV_SHKOLNIK).positions("О"))
    tokens = poem.encrypt("О" * n, NEKRASOV_SHKOLNIK).split(", ")
    assert len(set(tokens)) == n


def test_substitution_and_strict_mode():
    poem = PoemCipher()
    assert poem.decrypt(poem.encrypt("товарищ", NEKRASOV_SHKOLNIK), NEKRASOV_SHKOLNIK) == "ТОВАРИШ"
    with pytest.raises(ValueError, match="Щ"):
        poem.encrypt("щит", NEKRASOV_SHKOLNIK, substitute=False, strict=True)


def test_spaces_and_empty_message():
    poem = PoemCipher()
    assert poem.decrypt(poem.encrypt("  а \n б  ", NEKRASOV_SHKOLNIK), NEKRASOV_SHKOLNIK) == "А Б"
    assert poem.encrypt("", NEKRASOV_SHKOLNIK) == ""
    assert poem.encrypt("!!! 123", NEKRASOV_SHKOLNIK) == ""


def test_decrypt_rejects_invalid_codes():
    poem = PoemCipher()
    for token in ("0/5", "11/1", "abc", "1//2", "-1/3"):
        with pytest.raises(ValueError, match="Елемент №2"):
            poem.decrypt(f"4/3, {token}", NEKRASOV_SHKOLNIK)
    with pytest.raises(ValueError, match="порожня"):
        poem.decrypt("01/02", "А\nБВ", rows=2, cols=2)


def test_invalid_keys_and_data():
    poem = PoemCipher()
    with pytest.raises(ValueError):
        PoemKey(NEKRASOV_SHKOLNIK, rows=0)
    with pytest.raises(TypeError):
        PoemKey(NEKRASOV_SHKOLNIK, cols="10")
    assert poem.validate_key("123, !!!") is False
    assert poem.validate_key(None) is False
    with pytest.raises(TypeError):
        poem.encrypt(None, NEKRASOV_SHKOLNIK)


def test_split_words():
    assert split_words("М'ята, сім’ї — будь-який 2026р.!") == ["МЯТА", "СІМЇ", "БУДЬ", "ЯКИЙ", "Р"]


def test_beale_roundtrip():
    beale = BealeCipher()
    assert beale.decrypt("3, 1, 2, 0, 5, 4, 5", "Атака на базу о світанку") == "БАН СОС"
    msg = "Безпека інформаційних систем"
    assert beale.decrypt(beale.encrypt(msg, BOOK_SAMPLE), BOOK_SAMPLE) == msg.upper()


def test_beale_invalid_input():
    beale = BealeCipher()
    assert BealeKey(BOOK_SAMPLE).missing_letters(UK_ALPHABET) == ["Ь"]
    for token in ("-1", "1.5", "9999"):
        with pytest.raises(ValueError):
            beale.decrypt(token, "Атака на базу")


def test_ottendorf_roundtrip():
    ottendorf = OttendorfCipher()
    assert ottendorf.decrypt("1-1-1, 2-1-2, 0-0-0, 1-3-1", "Перший рядок тексту\n\nДругий рядок") == "ПР Т"
    enc = ottendorf.encrypt(UK_ALPHABET, BOOK_SAMPLE, strict=True, substitute=False)
    assert ottendorf.decrypt(enc, BOOK_SAMPLE) == UK_ALPHABET


def test_ottendorf_invalid_coordinates():
    ottendorf = OttendorfCipher()
    for token in ("1-1", "0-1-1", "9-1-1", "1-9-1", "1-1-99"):
        with pytest.raises(ValueError):
            ottendorf.decrypt(token, "Перший рядок\nДругий")


def test_keys_are_not_interchangeable():
    with pytest.raises(TypeError):
        BealeCipher().encrypt("а", OttendorfKey("абв"))
    with pytest.raises(TypeError):
        PoemCipher().decrypt("01/01", BealeKey("абв"))
