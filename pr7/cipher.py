from __future__ import annotations

import math
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Sequence, Tuple, Union

import clr  # noqa: F401  # pythonnet: завантажує .NET Framework

from System import Exception as NetException
from System.Security.Cryptography import RSACryptoServiceProvider

from pr1.cipher import BaseCipher, CipherEncDec
from pr5.cipher import SymmetricCipherError, UTF8, decode_input, encode_output, ensure_net_string

RSA_PADDINGS = ("OAEP", "PKCS1")
NET_KEY_SIZES = (512, 1024, 2048, 3072, 4096)
TEXT_FORMATS = ("Числа", "Текст (UTF-8)")
TEXTBOOK_MIN_BITS = 16
TEXTBOOK_MAX_BITS = 2048
MAX_DIGITS = 4000
MAX_XML_LENGTH = 100_000

WIKI_P, WIKI_Q, WIKI_E, WIKI_D = 61, 53, 17, 2753
WIKI_M, WIKI_C = 65, 2790

SMALL_PRIMES = tuple(p for p in range(2, 1000) if all(p % d for d in range(2, int(p ** 0.5) + 1)))

RSA_FACTORING_LIMITS = (
    ("до 64 біт", "ця програма, ρ-метод Полларда", "менше 0,1 с"),
    ("64-100 біт", "ця програма, ρ-метод Полларда", "секунди - хвилини"),
    ("до 200 біт (60 цифр)", "онлайн-калькулятор (ECM, SIQS)", "секунди"),
    ("~265 біт (80 цифр)", "онлайн-калькулятор (SIQS)", "хвилини"),
    ("~330 біт (100 цифр)", "онлайн-калькулятор (SIQS)", "години"),
    ("512 біт (RSA-155)", "GNFS, 1999 р.", "~8000 MIPS-років"),
    ("768 біт (RSA-768)", "GNFS, 2009 р.", "~2000 CPU-років"),
    ("829 біт (RSA-250)", "GNFS, 2020 р.", "~2700 ядро-років"),
    ("1024 біт і більше", "атака нереальна", "-"),
    ("2048 біт", "рекомендований мінімум", "-"),
)


class RSAError(ValueError):
    pass


def parse_int(value: Any, what: str = "Число", minimum: Optional[int] = 0) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{what} має бути цілим числом, а не bool.")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        text = value.strip().replace(" ", "").replace("_", "")
        if not text:
            raise RSAError(f"{what}: значення не задано.")
        if not re.fullmatch(r"[+-]?\d+", text):
            raise RSAError(f"{what} має бути цілим десятковим числом, а отримано {value.strip()[:40]!r}.")
        if len(text) > MAX_DIGITS:
            raise RSAError(f"{what} занадто велике (понад {MAX_DIGITS} цифр).")
        number = int(text)
    else:
        raise TypeError(f"{what} має бути цілим числом (int або str).")
    if minimum is not None and number < minimum:
        raise RSAError(f"{what} має бути не менше {minimum}, а отримано {number}.")
    return number


def parse_numbers(text: str, what: str = "Шифротекст") -> List[int]:
    if not isinstance(text, str):
        raise TypeError(f"{what} має бути рядком.")
    tokens = [t for t in re.split(r"[\s,;]+", text.strip()) if t]
    if not tokens:
        raise RSAError(f"{what} порожній: введіть числа через пробіл або кому.")
    return [parse_int(t, f"{what}, блок №{i}") for i, t in enumerate(tokens, 1)]


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    if bits < 3:
        raise RSAError("Просте число має містити щонайменше 3 біти.")
    while True:
        # Два старші біти гарантують, що добуток двох таких чисел має рівно 2*bits біт
        candidate = secrets.randbits(bits) | (0b11 << (bits - 2)) | 1
        if is_probable_prime(candidate):
            return candidate


@dataclass(frozen=True)
class RSAKey:
    n: int
    e: int
    d: Optional[int] = None
    p: Optional[int] = None
    q: Optional[int] = None

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def phi(self) -> Optional[int]:
        if self.p is None or self.q is None:
            return None
        return (self.p - 1) * (self.q - 1)

    @property
    def has_private(self) -> bool:
        return self.d is not None

    def public(self) -> "RSAKey":
        return RSAKey(self.n, self.e)


class TextbookRSA(CipherEncDec, BaseCipher):
    DEFAULT_E = (65537, 257, 17, 5, 3)

    @staticmethod
    def make_key(p: Any, q: Any, e: Any) -> RSAKey:
        p = parse_int(p, "p", 2)
        q = parse_int(q, "q", 2)
        e = parse_int(e, "e", 2)
        for value, name in ((p, "p"), (q, "q")):
            if not is_probable_prime(value):
                raise RSAError(f"{name} = {value} не є простим числом.")
        if p == q:
            raise RSAError("p і q мають бути різними: при p = q модуль n = p² легко розкласти (n = p·p).")
        phi = (p - 1) * (q - 1)
        if e >= phi:
            raise RSAError(f"Має виконуватися 1 < e < φ(n) = {phi}, а e = {e}.")
        g = math.gcd(e, phi)
        if g != 1:
            raise RSAError(f"e = {e} не взаємно просте з φ(n) = {phi} (НСД = {g}), обернений елемент d не існує.")
        return RSAKey(p * q, e, pow(e, -1, phi), p, q)

    @classmethod
    def generate_key(cls, bits: Any = 1024, e: Any = None) -> RSAKey:
        bits = parse_int(bits, "Розрядність ключа", TEXTBOOK_MIN_BITS)
        if bits > TEXTBOOK_MAX_BITS:
            raise RSAError(f"Розрядність ключа не може перевищувати {TEXTBOOK_MAX_BITS} біт.")
        candidates = (e,) if e not in (None, "") else cls.DEFAULT_E
        for _ in range(100):
            p = generate_prime(bits // 2)
            q = generate_prime(bits - bits // 2)
            if p == q:
                continue
            phi = (p - 1) * (q - 1)
            for value in candidates:
                value = parse_int(value, "e", 2)
                if value < phi and math.gcd(value, phi) == 1:
                    return cls.make_key(p, q, value)
        raise RSAError(f"Не вдалося підібрати p і q, взаємно прості з e = {e}. Спробуйте інше e.")

    @staticmethod
    def public_key(n: Any, e: Any) -> RSAKey:
        n = parse_int(n, "n", 6)
        e = parse_int(e, "e", 2)
        if e >= n:
            raise RSAError(f"Відкрита експонента e = {e} має бути менша за модуль n = {n}.")
        if n % 2 == 0:
            raise RSAError(f"n = {n} парне: модуль RSA є добутком двох непарних простих чисел.")
        return RSAKey(n, e)

    def validate_key(self, key: Any) -> bool:
        return isinstance(key, RSAKey) and key.n > 5 and 1 < key.e < key.n

    def validate_data(self, data: Any) -> bool:
        if isinstance(data, str):
            return bool(data)
        if isinstance(data, (list, tuple)):
            return bool(data) and all(isinstance(x, int) and not isinstance(x, bool) for x in data)
        return isinstance(data, int) and not isinstance(data, bool)

    def _check_key(self, key: Any, private: bool = False) -> RSAKey:
        if not self.validate_key(key):
            raise RSAError("Ключ RSA не задано або він некоректний: сформуйте ключ у діалозі.")
        if private and not key.has_private:
            raise RSAError("Для розшифрування потрібен закритий ключ d, а задано лише відкритий (n, e).")
        return key

    def _check_block(self, value: Any, key: RSAKey, what: str) -> int:
        value = parse_int(value, what)
        if value >= key.n:
            raise RSAError(f"{what} = {value} має бути менше модуля n = {key.n}.")
        return value

    def encrypt_int(self, m: Any, key: RSAKey) -> int:
        key = self._check_key(key)
        return pow(self._check_block(m, key, "Повідомлення m"), key.e, key.n)

    def decrypt_int(self, c: Any, key: RSAKey) -> int:
        key = self._check_key(key, private=True)
        return pow(self._check_block(c, key, "Шифроблок c"), key.d, key.n)

    @staticmethod
    def block_size(key: RSAKey) -> int:
        size = (key.n.bit_length() - 1) // 8
        if size < 1:
            raise RSAError(f"Модуль n = {key.n} замалий для тексту: потрібно n ≥ 256 (кожен байт має бути менший за n).")
        return size

    def encrypt_text(self, text: str, key: RSAKey) -> List[int]:
        key = self._check_key(key)
        if not isinstance(text, str):
            raise TypeError("Текст має бути рядком.")
        if not text:
            raise RSAError("Немає тексту для шифрування.")
        if "\x00" in text:
            raise RSAError("Текст не може містити символ NUL (\\x00): він використовується для доповнення блоків.")
        return [pow(m, key.e, key.n) for m in self.text_to_blocks(text, key)]

    def text_to_blocks(self, text: str, key: RSAKey) -> List[int]:
        try:
            data = text.encode("utf-8")
        except UnicodeEncodeError:
            raise RSAError("Текст містить некоректні символи Unicode (одиночні сурогати).") from None
        size = self.block_size(key)
        # Останній блок доповнюється нулями, які відкидаються після розшифрування
        data += b"\x00" * (-len(data) % size)
        return [int.from_bytes(data[i:i + size], "big") for i in range(0, len(data), size)]

    def decrypt_text(self, blocks: Sequence[int], key: RSAKey) -> str:
        key = self._check_key(key, private=True)
        if not blocks:
            raise RSAError("Шифротекст порожній.")
        size = self.block_size(key)
        out = bytearray()
        for i, c in enumerate(blocks, 1):
            m = self.decrypt_int(c, key)
            if m >= 256 ** size:
                raise RSAError(f"Блок №{i} розшифровано в число, більше за розмір блоку: ймовірно, невірний ключ.")
            out += m.to_bytes(size, "big")
        try:
            return bytes(out).rstrip(b"\x00").decode("utf-8")
        except UnicodeDecodeError:
            raise RSAError("Розшифровані байти не є текстом UTF-8: ймовірно, невірний ключ або пошкоджений шифротекст.") from None

    def encrypt(self, data: Union[str, int, Sequence[int]], key: RSAKey) -> Union[int, List[int]]:
        if isinstance(data, str):
            return self.encrypt_text(data, key)
        if not self.validate_data(data):
            raise TypeError("Дані мають бути рядком, цілим числом або непорожнім списком цілих чисел.")
        if isinstance(data, int):
            return self.encrypt_int(data, key)
        return [self.encrypt_int(m, key) for m in data]

    def decrypt(self, data: Union[int, Sequence[int]], key: RSAKey) -> Union[int, List[int]]:
        if isinstance(data, str) or not self.validate_data(data):
            raise TypeError("Шифротекст має бути цілим числом або непорожнім списком цілих чисел.")
        if isinstance(data, int):
            return self.decrypt_int(data, key)
        return [self.decrypt_int(c, key) for c in data]

    @staticmethod
    def describe(key: RSAKey) -> str:
        lines = []
        if key.p is not None:
            lines += [f"p = {key.p}", f"q = {key.q}",
                      f"n = p·q = {key.n} ({key.bits} біт)",
                      f"φ(n) = (p−1)(q−1) = {key.phi}"]
        else:
            lines.append(f"n = {key.n} ({key.bits} біт)")
        lines.append(f"e = {key.e}")
        if key.d is not None:
            lines.append(f"d = e^(-1) mod φ(n) = {key.d}")
            if key.phi:
                lines.append(f"Перевірка: e·d mod φ(n) = {key.e * key.d % key.phi}")
        lines.append(f"Відкритий ключ: (e, n) = ({key.e}, {key.n})")
        if key.d is not None:
            lines.append(f"Закритий ключ: (d, n) = ({key.d}, {key.n})")
        return "\n".join(lines)


def _translate_net(exc: BaseException, decrypting: bool = False) -> RSAError:
    if decrypting:
        return RSAError("Не вдалося розшифрувати: невірний закритий ключ, режим доповнення або пошкоджений шифротекст.")
    message = getattr(exc, "Message", None) or str(exc)
    return RSAError(f"Помилка криптопровайдера .NET: {message.strip()}")


def _new_provider(key_size: Optional[int] = None) -> RSACryptoServiceProvider:
    provider = RSACryptoServiceProvider(key_size) if key_size else RSACryptoServiceProvider()
    # Ключ живе лише в пам'яті і не зберігається у сховищі ключів Windows
    provider.PersistKeyInCsp = False
    return provider


class NetRSACipher(CipherEncDec, BaseCipher):
    def __init__(self, key_size: Optional[int] = 1024, xml: Optional[str] = None):
        self.provider: Optional[RSACryptoServiceProvider] = None
        if xml is not None:
            self.import_xml(xml)
        elif key_size is not None:
            self.generate(key_size)

    @staticmethod
    def legal_key_sizes() -> Tuple[int, int, int]:
        ks = _new_provider().LegalKeySizes[0]
        return ks.MinSize, ks.MaxSize, ks.SkipSize

    @classmethod
    def check_key_size(cls, key_size: Any) -> int:
        key_size = parse_int(key_size, "Розмір ключа", 1)
        low, high, step = cls.legal_key_sizes()
        if not low <= key_size <= high or (key_size - low) % step:
            raise RSAError(f"Розмір ключа RSA має бути від {low} до {high} біт з кроком {step}, а отримано {key_size}.")
        return key_size

    def generate(self, key_size: Any = 1024):
        key_size = self.check_key_size(key_size)
        try:
            self._set_provider(_new_provider(key_size))
        except NetException as e:
            raise _translate_net(e) from None

    def _set_provider(self, provider: RSACryptoServiceProvider):
        if self.provider is not None:
            self.provider.Dispose()
        self.provider = provider

    def _require(self) -> RSACryptoServiceProvider:
        if self.provider is None:
            raise RSAError("Ключ RSA ще не сформовано: згенеруйте пару ключів або імпортуйте відкритий ключ.")
        return self.provider

    @property
    def key_size(self) -> int:
        return self._require().KeySize

    @property
    def has_private(self) -> bool:
        return not self._require().PublicOnly

    @staticmethod
    def _load_xml(xml: Any) -> RSACryptoServiceProvider:
        xml = ensure_net_string(xml, "XML ключа").strip()
        if not xml:
            raise RSAError("XML ключа порожній.")
        if len(xml) > MAX_XML_LENGTH:
            raise RSAError(f"XML ключа занадто довгий (понад {MAX_XML_LENGTH} символів).")
        if "<RSAKeyValue>" not in xml or "<Modulus>" not in xml or "<Exponent>" not in xml:
            raise RSAError("XML не схожий на ключ RSA: очікуються елементи <RSAKeyValue>, <Modulus> та <Exponent>.")
        provider = _new_provider()
        try:
            provider.FromXmlString(xml)
        except NetException as e:
            provider.Dispose()
            raise RSAError(f"Некоректний XML ключа RSA: {e.Message.strip()}") from None
        return provider

    def import_xml(self, xml: Any):
        self._set_provider(self._load_xml(xml))

    def export_xml(self, include_private: bool = False) -> str:
        provider = self._require()
        if include_private and provider.PublicOnly:
            raise RSAError("Імпортовано лише відкритий ключ: закритого ключа немає.")
        return str(provider.ToXmlString(include_private))

    def public_numbers(self) -> Tuple[int, int]:
        params = self._require().ExportParameters(False)
        return int.from_bytes(bytes(params.Modulus), "big"), int.from_bytes(bytes(params.Exponent), "big")

    def max_message_size(self, padding: str = "OAEP") -> int:
        self._check_padding(padding)
        k = self.key_size // 8
        # OAEP з SHA-1: 2·20 + 2 байти службових даних; PKCS#1 v1.5: 11 байт
        return k - 42 if padding == "OAEP" else k - 11

    @staticmethod
    def _check_padding(padding: Any):
        if padding not in RSA_PADDINGS:
            raise RSAError(f"Невідомий режим доповнення: {padding!r}. Доступні: {', '.join(RSA_PADDINGS)}.")

    def validate_key(self, key: Any) -> bool:
        try:
            self._load_xml(key).Dispose()
            return True
        except (TypeError, RSAError, SymmetricCipherError):
            return False

    def validate_data(self, data: Any) -> bool:
        return isinstance(data, (str, bytes, bytearray)) and len(data) > 0

    def encrypt_bytes(self, data: bytes, padding: str = "OAEP", public_xml: Optional[str] = None) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Дані для шифрування мають бути байтами (bytes).")
        if not data:
            raise RSAError("Немає даних для шифрування.")
        self._check_padding(padding)
        target = NetRSACipher(None, public_xml) if public_xml is not None else self
        limit = target.max_message_size(padding)
        if len(data) > limit:
            raise RSAError(
                f"Повідомлення завелике: {len(data)} байт, а ключ {target.key_size} біт з доповненням {padding} "
                f"дозволяє не більше {limit} байт."
            )
        try:
            return bytes(target._require().Encrypt(bytes(data), padding == "OAEP"))
        except NetException as e:
            raise _translate_net(e) from None

    def decrypt_bytes(self, data: bytes, padding: str = "OAEP") -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Шифротекст має бути байтами (bytes).")
        if not data:
            raise RSAError("Шифротекст порожній.")
        self._check_padding(padding)
        provider = self._require()
        if provider.PublicOnly:
            raise RSAError("Для розшифрування потрібен закритий ключ, а імпортовано лише відкритий.")
        k = provider.KeySize // 8
        if len(data) != k:
            raise RSAError(f"Довжина шифротексту має дорівнювати розміру ключа ({k} байт), а отримано {len(data)}.")
        try:
            return bytes(provider.Decrypt(bytes(data), padding == "OAEP"))
        except NetException as e:
            raise _translate_net(e, decrypting=True) from None

    def encrypt(self, data: Any, key: Optional[str] = None, padding: str = "OAEP") -> bytes:
        if isinstance(data, str):
            data = bytes(UTF8.GetBytes(ensure_net_string(data))) if data else b""
        return self.encrypt_bytes(data, padding, key)

    def decrypt(self, data: bytes, key: Optional[str] = None, padding: str = "OAEP") -> str:
        if key is not None:
            return NetRSACipher(None, key).decrypt(data, None, padding)
        plain = self.decrypt_bytes(data, padding)
        try:
            return str(UTF8.GetString(plain))
        except NetException:
            raise RSAError("Розшифровані байти не є текстом UTF-8.") from None

    def encrypt_text(self, text: str, padding: str = "OAEP", public_xml: Optional[str] = None, fmt: str = "Base64") -> str:
        try:
            return encode_output(self.encrypt(text, public_xml, padding), fmt)
        except SymmetricCipherError as e:
            raise RSAError(str(e)) from None

    def decrypt_text(self, text: str, padding: str = "OAEP", fmt: str = "Base64") -> str:
        try:
            data = decode_input(text, fmt)
        except SymmetricCipherError as e:
            raise RSAError(str(e)) from None
        return self.decrypt(data, None, padding)


@dataclass
class AttackResult:
    key: RSAKey
    method: str
    elapsed: float


@dataclass
class BenchmarkRow:
    bits: int
    n: int
    p: Optional[int]
    q: Optional[int]
    elapsed: float
    success: bool


class RSAFactorAttack:
    TRIAL_LIMIT = 100_000
    FERMAT_STEPS = 10_000

    @staticmethod
    def _trial_division(n: int, limit: int) -> Optional[int]:
        if n % 2 == 0:
            return 2
        for d in range(3, min(limit, math.isqrt(n)) + 1, 2):
            if n % d == 0:
                return d
        return None

    @staticmethod
    def _fermat(n: int, steps: int) -> Optional[int]:
        # Швидко знаходить p і q, якщо вони близькі одне до одного
        a = math.isqrt(n)
        if a * a < n:
            a += 1
        for _ in range(steps):
            b2 = a * a - n
            b = math.isqrt(b2)
            if b * b == b2:
                return a - b
            a += 1
        return None

    @staticmethod
    def _pollard_brent(n: int, deadline: float) -> Optional[int]:
        while time.perf_counter() < deadline:
            y, c, m = secrets.randbelow(n - 1) + 1, secrets.randbelow(n - 1) + 1, 128
            g = r = q = 1
            x = ys = y
            while g == 1:
                x = y
                for _ in range(r):
                    y = (y * y + c) % n
                k = 0
                while k < r and g == 1:
                    if time.perf_counter() > deadline:
                        return None
                    ys = y
                    for _ in range(min(m, r - k)):
                        y = (y * y + c) % n
                        q = q * abs(x - y) % n
                    g = math.gcd(q, n)
                    k += m
                r *= 2
            if g == n:
                g = 1
                while g == 1:
                    ys = (ys * ys + c) % n
                    g = math.gcd(abs(x - ys), n)
            if 1 < g < n:
                return g
        return None

    def factorize(self, n: Any, time_limit: float = 10.0) -> Tuple[int, int, str]:
        n = parse_int(n, "n", 6)
        if not isinstance(time_limit, (int, float)) or isinstance(time_limit, bool) or time_limit <= 0:
            raise RSAError("Обмеження часу має бути додатним числом секунд.")
        if is_probable_prime(n):
            raise RSAError(f"n = {n} є простим числом, тому не може бути модулем RSA (n = p·q).")
        root = math.isqrt(n)
        if root * root == n and is_probable_prime(root):
            raise RSAError(f"n = {root}² - квадрат простого числа (p = q), це некоректний модуль RSA.")

        deadline = time.perf_counter() + time_limit
        for method, finder in (
            ("пробне ділення", lambda: self._trial_division(n, self.TRIAL_LIMIT)),
            ("метод Ферма", lambda: self._fermat(n, self.FERMAT_STEPS)),
            ("ρ-метод Полларда (Брента)", lambda: self._pollard_brent(n, deadline)),
        ):
            p = finder()
            if p:
                p, q = sorted((p, n // p))
                if not (is_probable_prime(p) and is_probable_prime(q)):
                    raise RSAError(f"n = {p} · {q}, але множники не обидва прості: n не є модулем RSA.")
                return p, q, method
        raise RSAError(f"За {time_limit:g} с не вдалося розкласти n ({n.bit_length()} біт): ключ надто великий для цієї атаки.")

    def attack(self, n: Any, e: Any, time_limit: float = 10.0) -> AttackResult:
        public = TextbookRSA.public_key(n, e)
        start = time.perf_counter()
        p, q, method = self.factorize(public.n, time_limit)
        elapsed = time.perf_counter() - start
        phi = (p - 1) * (q - 1)
        if math.gcd(public.e, phi) != 1:
            raise RSAError(f"n = {p}·{q}, але e = {public.e} не взаємно просте з φ(n) = {phi}: ключ некоректний.")
        return AttackResult(RSAKey(public.n, public.e, pow(public.e, -1, phi), p, q), method, elapsed)

    def benchmark(self, bit_sizes: Sequence[int], time_limit: float = 5.0,
                  on_row: Optional[Callable[[BenchmarkRow], None]] = None) -> List[BenchmarkRow]:
        rows = []
        for bits in bit_sizes:
            key = TextbookRSA.generate_key(bits)
            start = time.perf_counter()
            try:
                p, q, _ = self.factorize(key.n, time_limit)
                row = BenchmarkRow(bits, key.n, p, q, time.perf_counter() - start, True)
            except RSAError:
                row = BenchmarkRow(bits, key.n, None, None, time.perf_counter() - start, False)
            rows.append(row)
            if on_row:
                on_row(row)
        return rows
