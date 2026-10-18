from __future__ import annotations

import random
import re
import secrets
import unicodedata
from abc import abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from pr1.cipher import BaseCipher, CipherEncDec

Coord = Tuple[int, ...]

# Літери-замінники у порядку пріоритету
SUBSTITUTIONS: Dict[str, Tuple[str, ...]] = {
    "Щ": ("Ш",),
    "Ґ": ("Г",),
    "Є": ("Е", "Э"),
    "Ї": ("І", "И"),
    "І": ("И", "Ї"),
    "И": ("І", "Ы"),
    "Й": ("И", "І"),
    "Ё": ("Е",),
    "Ъ": ("Ь",),
    "Ь": ("Ъ",),
    "Ы": ("И", "І"),
    "Э": ("Е", "Є"),
    "Е": ("Э", "Є", "Ё"),
}

APOSTROPHES = "'’ʼ`"

UK_ALPHABET = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
RU_ALPHABET = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
EN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def normalize_text(text: str) -> str:
    # NFC: «й», записана як «и» + комбінований знак, стає однією літерою
    return unicodedata.normalize("NFC", text)


def normalize_char(ch: str) -> str:
    # ß.upper() == "SS" — такі літери лишаються як є, щоб займати одну клітинку
    up = ch.upper()
    return up if len(up) == 1 else ch


def extract_letters(line: str) -> List[str]:
    return [normalize_char(c) for c in normalize_text(line) if c.isalpha()]


def split_words(line: str) -> List[str]:
    # апостроф усередині слова не розриває його: м'ята → МЯТА
    text = normalize_text(line)
    words: List[str] = []
    cur: List[str] = []
    for i, ch in enumerate(text):
        if ch.isalpha():
            cur.append(normalize_char(ch))
        elif ch in APOSTROPHES and cur and i + 1 < len(text) and text[i + 1].isalpha():
            continue
        elif cur:
            words.append("".join(cur))
            cur = []
    if cur:
        words.append("".join(cur))
    return words


def _check_text(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{what} повинен бути рядком (str).")
    return value


class BookKey:
    def __init__(self):
        self._index: Dict[str, List[Coord]] = {}

    def _register(self, ch: str, coord: Coord):
        self._index.setdefault(ch, []).append(coord)

    def contains(self, ch: str) -> bool:
        return ch in self._index

    def positions(self, ch: str) -> List[Coord]:
        return list(self._index.get(ch, []))

    @property
    def alphabet(self) -> set:
        return set(self._index)

    def letter_counts(self) -> Dict[str, int]:
        counts = {ch: len(p) for ch, p in self._index.items()}
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    def missing_letters(self, alphabet: str) -> List[str]:
        return [ch for ch in alphabet if ch not in self._index]

    @abstractmethod
    def char_at(self, coord: Coord) -> str: ...


class PoemKey(BookKey):
    MAX_DIM = 99  # координати двозначні

    def __init__(self, poem: str, rows: int = 10, cols: int = 10):
        super().__init__()
        _check_text(poem, "Вірш-ключ")
        self.rows = self._check_dim(rows, "рядків")
        self.cols = self._check_dim(cols, "стовпців")

        lines = [extract_letters(line) for line in normalize_text(poem).splitlines()]
        lines = [letters for letters in lines if letters][: self.rows]
        if not lines:
            raise ValueError("Вірш-ключ не містить жодної літери.")

        self.grid: List[List[str]] = []
        for letters in lines:
            row = letters[: self.cols]
            self.grid.append(row + [""] * (self.cols - len(row)))
        while len(self.grid) < self.rows:
            self.grid.append([""] * self.cols)

        for r, row in enumerate(self.grid, start=1):
            for c, ch in enumerate(row, start=1):
                if ch:
                    self._register(ch, (r, c))

    @classmethod
    def _check_dim(cls, value: Any, what: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"Кількість {what} повинна бути цілим числом.")
        if not 1 <= value <= cls.MAX_DIM:
            raise ValueError(f"Кількість {what} повинна бути в межах 1..{cls.MAX_DIM}.")
        return value

    def char_at(self, coord: Coord) -> str:
        r, c = coord
        if not (1 <= r <= self.rows and 1 <= c <= self.cols):
            raise ValueError(f"координата {r}/{c} поза межами таблиці {self.rows}×{self.cols}")
        ch = self.grid[r - 1][c - 1]
        if not ch:
            raise ValueError(f"клітинка {r}/{c} порожня")
        return ch


class BealeKey(BookKey):
    def __init__(self, text: str):
        super().__init__()
        _check_text(text, "Текст-ключ")
        self.words: List[str] = []
        for line in normalize_text(text).splitlines():
            self.words.extend(split_words(line))
        if not self.words:
            raise ValueError("Текст-ключ не містить жодного слова.")
        for n, word in enumerate(self.words, start=1):
            self._register(word[0], (n,))

    def char_at(self, coord: Coord) -> str:
        (n,) = coord
        if not 1 <= n <= len(self.words):
            raise ValueError(f"слова №{n} немає (у ключі {len(self.words)} слів)")
        return self.words[n - 1][0]


class OttendorfKey(BookKey):
    def __init__(self, text: str):
        super().__init__()
        _check_text(text, "Текст-ключ")
        # нумеруються лише рядки, що містять слова
        self.lines: List[List[str]] = [
            words for words in (split_words(line) for line in normalize_text(text).splitlines()) if words
        ]
        if not self.lines:
            raise ValueError("Текст-ключ не містить жодного слова.")
        for li, words in enumerate(self.lines, start=1):
            for wi, word in enumerate(words, start=1):
                for ci, ch in enumerate(word, start=1):
                    self._register(ch, (li, wi, ci))

    def char_at(self, coord: Coord) -> str:
        li, wi, ci = coord
        if not 1 <= li <= len(self.lines):
            raise ValueError(f"рядка {li} немає (у ключі {len(self.lines)} рядків)")
        words = self.lines[li - 1]
        if not 1 <= wi <= len(words):
            raise ValueError(f"у рядку {li} немає слова {wi} (слів: {len(words)})")
        word = words[wi - 1]
        if not 1 <= ci <= len(word):
            raise ValueError(f"у слові {li}-{wi} «{word}» немає літери {ci}")
        return word[ci - 1]


@dataclass
class EncodingReport:
    letters: int = 0
    spaces: int = 0
    skipped_symbols: List[str] = field(default_factory=list)
    substituted: Dict[str, str] = field(default_factory=dict)
    missing: List[str] = field(default_factory=list)

    @property
    def lossless(self) -> bool:
        return not (self.missing or self.substituted or self.skipped_symbols)

    def summary(self) -> str:
        parts = [f"Літер: {self.letters}", f"пробілів: {self.spaces}"]
        if self.substituted:
            parts.append("заміни: " + ", ".join(f"{a}→{b}" for a, b in self.substituted.items()))
        if self.missing:
            parts.append("відсутні в ключі (пропущено): " + " ".join(self.missing))
        if self.skipped_symbols:
            parts.append("пропущені символи: " + " ".join(repr(s) for s in self.skipped_symbols))
        return "; ".join(parts)


class BookCipherBase(CipherEncDec, BaseCipher):
    KEY_CLASS: type = BookKey
    SPACE_COORD: Coord = ()
    TOKEN_SEPARATOR = ", "
    TOKEN_SPLIT_RE = re.compile(r"[,;\r\n]")

    @abstractmethod
    def build_key(self, key: Any, **key_params) -> BookKey: ...

    @abstractmethod
    def format_coord(self, coord: Coord) -> str: ...

    @abstractmethod
    def parse_token(self, token: str) -> Coord: ...

    def _resolve_key(self, key: Any, **key_params) -> BookKey:
        if isinstance(key, self.KEY_CLASS):
            return key
        if isinstance(key, BookKey):
            raise TypeError(f"Очікується ключ {self.KEY_CLASS.__name__}, отримано {type(key).__name__}.")
        return self.build_key(key, **key_params)

    def validate_key(self, key: Any, **key_params) -> bool:
        try:
            self._resolve_key(key, **key_params)
            return True
        except (TypeError, ValueError):
            return False

    def validate_data(self, data: Any) -> bool:
        return isinstance(data, str)

    @staticmethod
    def _resolve_char(ch: str, key: BookKey, substitute: bool) -> Optional[str]:
        if key.contains(ch):
            return ch
        if substitute:
            for alt in SUBSTITUTIONS.get(ch, ()):
                if key.contains(alt):
                    return alt
        return None

    def _plan(self, data: str, key: BookKey, substitute: bool, keep_spaces: bool) -> Tuple[List[Optional[str]], EncodingReport]:
        # None у результаті позначає пробіл
        report = EncodingReport()
        items: List[Optional[str]] = []
        for raw in normalize_text(data):
            if raw.isspace():
                # серія пробілів/переносів → один пробіл, без пробілів на краях
                if keep_spaces and items and items[-1] is not None:
                    items.append(None)
                continue
            if not raw.isalpha():
                if raw not in report.skipped_symbols:
                    report.skipped_symbols.append(raw)
                continue
            ch = normalize_char(raw)
            report.letters += 1
            resolved = self._resolve_char(ch, key, substitute)
            if resolved is None:
                if ch not in report.missing:
                    report.missing.append(ch)
                continue
            if resolved != ch:
                report.substituted[ch] = resolved
            items.append(resolved)
        while items and items[-1] is None:
            items.pop()
        report.spaces = items.count(None)
        return items, report

    def analyze(self, data: str, key: Any, *, substitute: bool = True, keep_spaces: bool = True, **key_params) -> EncodingReport:
        if not self.validate_data(data):
            raise TypeError("Повідомлення повинно бути рядком (str).")
        return self._plan(data, self._resolve_key(key, **key_params), substitute, keep_spaces)[1]

    def encrypt(
        self,
        data: str,
        key: Any,
        *,
        seed: Optional[int] = None,
        rng: Optional[random.Random] = None,
        substitute: bool = True,
        keep_spaces: bool = True,
        strict: bool = False,
        avoid_repeats: bool = True,
        **key_params,
    ) -> str:
        if not self.validate_data(data):
            raise TypeError("Повідомлення для шифрування повинно бути рядком (str).")
        book = self._resolve_key(key, **key_params)
        items, report = self._plan(data, book, substitute, keep_spaces)

        if strict and (report.missing or report.skipped_symbols):
            problems = report.missing + [repr(s) for s in report.skipped_symbols]
            raise ValueError("Неможливо закодувати символи (відсутні в ключі): " + " ".join(problems))

        # seed / rng — лише для відтворюваних тестів
        if rng is None:
            rng = random.Random(seed) if seed is not None else secrets.SystemRandom()

        # avoid_repeats: координата літери не повторюється, доки не використано всі її входження
        pools: Dict[str, List[Coord]] = {}
        tokens: List[str] = []
        for ch in items:
            if ch is None:
                tokens.append(self.format_coord(self.SPACE_COORD))
                continue
            if avoid_repeats:
                pool = pools.get(ch)
                if not pool:
                    pool = pools[ch] = book.positions(ch)
                coord = pool.pop(rng.randrange(len(pool)))
            else:
                coord = rng.choice(book.positions(ch))
            tokens.append(self.format_coord(coord))
        return self.TOKEN_SEPARATOR.join(tokens)

    def decrypt(self, data: str, key: Any, **key_params) -> str:
        if not self.validate_data(data):
            raise TypeError("Шифрограма повинна бути рядком (str).")
        book = self._resolve_key(key, **key_params)

        result: List[str] = []
        for n, raw in enumerate(self.TOKEN_SPLIT_RE.split(data), start=1):
            token = raw.strip()
            if not token:
                continue  # кома в кінці або подвійні коми
            try:
                coord = self.parse_token(token)
                result.append(" " if coord == self.SPACE_COORD else book.char_at(coord))
            except ValueError as e:
                raise ValueError(f"Елемент №{n} «{token}»: {e}") from None
        return "".join(result)


class PoemCipher(BookCipherBase):
    KEY_CLASS = PoemKey
    SPACE_COORD = (0, 0)
    TOKEN_RE = re.compile(r"^([0-9]{1,2})\s*/\s*([0-9]{1,2})$")

    def build_key(self, key: Any, rows: int = 10, cols: int = 10) -> PoemKey:
        if not isinstance(key, str):
            raise TypeError("Ключ віршованого шифру — текст вірша (str) або PoemKey.")
        return PoemKey(key, rows, cols)

    def format_coord(self, coord: Coord) -> str:
        r, c = coord
        return f"{r:02d}/{c:02d}"

    def parse_token(self, token: str) -> Coord:
        m = self.TOKEN_RE.match(token)
        if not m:
            raise ValueError("очікується формат РР/СС (наприклад 04/03)")
        r, c = int(m.group(1)), int(m.group(2))
        if (r == 0) != (c == 0):
            raise ValueError("нульова координата допустима лише як код пробілу 00/00")
        return r, c


class BealeCipher(BookCipherBase):
    """Літера → номер слова тексту-ключа, яке починається з цієї літери."""

    KEY_CLASS = BealeKey
    SPACE_COORD = (0,)
    TOKEN_RE = re.compile(r"^[0-9]{1,9}$")

    def build_key(self, key: Any) -> BealeKey:
        if not isinstance(key, str):
            raise TypeError("Ключ шифру Біла — текст книги (str) або BealeKey.")
        return BealeKey(key)

    def format_coord(self, coord: Coord) -> str:
        return str(coord[0])

    def parse_token(self, token: str) -> Coord:
        if not self.TOKEN_RE.match(token):
            raise ValueError("очікується номер слова (ціле невід'ємне число)")
        return (int(token),)


class OttendorfCipher(BookCipherBase):
    """Літера → «рядок-слово-літера» у тексті-ключі."""

    KEY_CLASS = OttendorfKey
    SPACE_COORD = (0, 0, 0)
    TOKEN_RE = re.compile(r"^([0-9]{1,6})\s*-\s*([0-9]{1,6})\s*-\s*([0-9]{1,6})$")

    def build_key(self, key: Any) -> OttendorfKey:
        if not isinstance(key, str):
            raise TypeError("Ключ шифру Оттендорфа — текст книги (str) або OttendorfKey.")
        return OttendorfKey(key)

    def format_coord(self, coord: Coord) -> str:
        return "-".join(str(v) for v in coord)

    def parse_token(self, token: str) -> Coord:
        m = self.TOKEN_RE.match(token)
        if not m:
            raise ValueError("очікується формат Р-С-Л (рядок-слово-літера, наприклад 3-2-5)")
        coord = tuple(int(g) for g in m.groups())
        if 0 in coord and coord != self.SPACE_COORD:
            raise ValueError("нульова координата допустима лише як код пробілу 0-0-0")
        return coord


NEKRASOV_SHKOLNIK = (
    "Ну, пошел же, ради бога!\n"
    "Небо, ельник и песок —\n"
    "Невеселая дорога...\n"
    "Эй! садись ко мне, дружок!\n"
    "Ноги босы, грязно тело,\n"
    "И едва прикрыта грудь...\n"
    "Не стыдися! что за дело?\n"
    "Это многих славный путь.\n"
    "Вижу я в котомке книжку.\n"
    "Так, учиться ты идешь..."
)

SHEVCHENKO_ZAPOVIT = (
    "Як умру, то поховайте\n"
    "Мене на могилі,\n"
    "Серед степу широкого,\n"
    "На Вкраїні милій,\n"
    "Щоб лани широкополі,\n"
    "І Дніпро, і кручі\n"
    "Було видно, було чути,\n"
    "Як реве ревучий.\n"
    "Як понесе з України\n"
    "У синєє море\n"
    "Кров ворожу... отойді я\n"
    "І лани і гори —\n"
    "Все покину і полину\n"
    "До самого Бога\n"
    "Молитися... а до того\n"
    "Я не знаю Бога.\n"
    "Поховайте та вставайте,\n"
    "Кайдани порвіте\n"
    "І вражою злою кров'ю\n"
    "Волю окропіте.\n"
    "І мене в сім'ї великій,\n"
    "В сім'ї вольній, новій,\n"
    "Не забудьте пом'янути\n"
    "Незлим тихим словом."
)

# Містить слова на кожну літеру укр. алфавіту (крім Ь) — для шифру Біла
BOOK_SAMPLE = (
    "Безпека інформаційних систем — це наука про захист даних від зловмисників.\n"
    "Криптографія вивчає шифри, ключі та алгоритми, які роблять таємне листування можливим.\n"
    "Хакер шукає вразливості, а фахівець усуває їх раніше, ніж ґрунтовно спланована атака вдасться.\n"
    "Йдеться про цілісність, конфіденційність і доступність — три опори захисту.\n"
    "Жоден ключ не повинен потрапити до чужих рук, бо тоді шифр втрачає сенс.\n"
    "Ефективний шифр є стійким до частотного аналізу, а книжковий шифр, на жаль, ні.\n"
    "Юристи, гравці й інженери щодня оцінюють ризики, їхні рішення обґрунтовані.\n"
    "Ирій чекає на птахів, яких ніхто не зупинить, отже, й повідомлення знайде адресата.\n"
    "Європа, Україна та світ шукають нові методи обміну секретами."
)

POEM_PRESETS: Dict[str, str] = {
    "Некрасов «Школьник» (приклад з методички)": NEKRASOV_SHKOLNIK,
    "Шевченко «Заповіт»": SHEVCHENKO_ZAPOVIT,
}
