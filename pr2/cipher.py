from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, List, Optional, Sequence, Tuple, Union

from pr1.cipher import CaesarCipher, BinaryCaesarCipher


class KeyType(str, Enum):
    LINEAR = "linear"
    NON_LINEAR = "non_linear"
    MOTTO = "motto"


@dataclass
class TrithemiusKey:
    key_type: KeyType
    linear_coeffs: Optional[Tuple[int, int]] = None
    nonlinear_coeffs: Optional[Tuple[int, int, int]] = None
    motto: Optional[str] = None

    @classmethod
    def linear(cls, a: int, b: int) -> "TrithemiusKey":
        return cls(KeyType.LINEAR, linear_coeffs=(int(a), int(b)))

    @classmethod
    def non_linear(cls, a: int, b: int, c: int) -> "TrithemiusKey":
        return cls(KeyType.NON_LINEAR, nonlinear_coeffs=(int(a), int(b), int(c)))

    @classmethod
    def from_motto(cls, motto: str) -> "TrithemiusKey":
        clean = motto.strip()
        if not clean:
            raise ValueError("Гасло не може бути порожнім.")
        return cls(KeyType.MOTTO, motto=clean)

    @classmethod
    def from_any(cls, raw: Any) -> "TrithemiusKey":
        if isinstance(raw, TrithemiusKey):
            return raw

        if isinstance(raw, bool):
            raise ValueError("Ключ не може бути логічним типом (bool).")

        if isinstance(raw, (tuple, list)):
            if len(raw) == 2:
                try:
                    return cls.linear(int(raw[0]), int(raw[1]))
                except (ValueError, TypeError) as e:
                    raise ValueError(f"Коефіцієнти лінійного ключа мають бути цілими числами: {raw}") from e
            elif len(raw) == 3:
                try:
                    return cls.non_linear(int(raw[0]), int(raw[1]), int(raw[2]))
                except (ValueError, TypeError) as e:
                    raise ValueError(f"Коефіцієнти нелінійного ключа мають бути цілими числами: {raw}") from e
            else:
                raise ValueError(f"Векторний ключ повинен мати розмірність 2 або 3, отримано {len(raw)}: {raw}")

        if isinstance(raw, dict):
            k_type = raw.get("type")
            if k_type == KeyType.LINEAR or "A" in raw and "B" in raw and "C" not in raw:
                return cls.linear(int(raw["A"]), int(raw["B"]))
            if k_type == KeyType.NON_LINEAR or ("A" in raw and "B" in raw and "C" in raw):
                return cls.non_linear(int(raw["A"]), int(raw["B"]), int(raw["C"]))
            if k_type == KeyType.MOTTO or "motto" in raw:
                return cls.from_motto(str(raw.get("motto", "")))

        if isinstance(raw, str):
            clean = raw.strip()
            if not clean:
                raise ValueError("Ключ не може бути порожнім рядком.")

            nums = re.findall(r"-?\d+", clean)
            is_num_vector = bool(nums) and re.fullmatch(r"[\s\(\)\[\],\-\d]+", clean) is not None
            if is_num_vector:
                if len(nums) == 2:
                    return cls.linear(int(nums[0]), int(nums[1]))
                if len(nums) == 3:
                    return cls.non_linear(int(nums[0]), int(nums[1]), int(nums[2]))

            return cls.from_motto(clean)

        raise ValueError(f"Невідомий формат ключа: {type(raw).__name__} ({raw})")

    @classmethod
    def validate(cls, raw: Any) -> bool:
        try:
            cls.from_any(raw)
            return True
        except Exception:
            return False

    def get_shift(self, p: int, alphabet_len: int, motto_shifts: Optional[Sequence[int]] = None) -> int:
        if self.key_type == KeyType.LINEAR:
            a, b = self.linear_coeffs  # type: ignore
            return (a * p + b) % alphabet_len
        elif self.key_type == KeyType.NON_LINEAR:
            a, b, c = self.nonlinear_coeffs  # type: ignore
            return (a * (p ** 2) + b * p + c) % alphabet_len
        elif self.key_type == KeyType.MOTTO:
            if not motto_shifts:
                return 0
            return motto_shifts[p % len(motto_shifts)] % alphabet_len
        return 0

    def formula_display(self) -> str:
        if self.key_type == KeyType.LINEAR:
            a, b = self.linear_coeffs  # type: ignore
            b_sign = f"+ {b}" if b >= 0 else f"- {abs(b)}"
            return f"k(p) = {a}·p {b_sign}"
        elif self.key_type == KeyType.NON_LINEAR:
            a, b, c = self.nonlinear_coeffs  # type: ignore
            b_sign = f"+ {b}·p" if b >= 0 else f"- {abs(b)}·p"
            c_sign = f"+ {c}" if c >= 0 else f"- {abs(c)}"
            return f"k(p) = {a}·p² {b_sign} {c_sign}"
        elif self.key_type == KeyType.MOTTO:
            return f"Гасло: «{self.motto}»"
        return "Невідомий ключ"

    def to_vector(self) -> Union[Tuple[int, int], Tuple[int, int, int], str]:
        if self.key_type == KeyType.LINEAR:
            return self.linear_coeffs  # type: ignore
        if self.key_type == KeyType.NON_LINEAR:
            return self.nonlinear_coeffs  # type: ignore
        return self.motto or ""


class TrithemiusCipher(CaesarCipher):
    def validate_key(self, key: Any) -> bool:
        return TrithemiusKey.validate(key)

    def _extract_motto_shifts(self, motto: str, lang: str = "auto") -> List[int]:
        shifts: List[int] = []
        uk_matches = [self.UK_LOWER.index(c.lower()) for c in motto if c.lower() in self.UK_LOWER]
        en_matches = [self.EN_LOWER.index(c.lower()) for c in motto if c.lower() in self.EN_LOWER]

        if lang == "uk":
            shifts = uk_matches
        elif lang == "en":
            shifts = en_matches
        else:
            if len(uk_matches) >= len(en_matches) and uk_matches:
                shifts = uk_matches
            elif en_matches:
                shifts = en_matches

        if not shifts:
            raise ValueError(
                f"Гасло '{motto}' не містить літер обраного алфавіту ({lang})."
            )
        return shifts

    def encrypt(
        self,
        data: str,
        key: Any,
        lang: str = "auto",
        letter_only: bool = True,
        start_pos: int = 0,
    ) -> str:
        if not self.validate_data(data):
            raise TypeError("Дані для шифрування повинні бути рядком (str).")
        if not self.validate_key(key):
            raise ValueError(f"Невалідний ключ Тритеміуса: {key}")

        parsed_key = TrithemiusKey.from_any(key)
        motto_shifts: Optional[List[int]] = None
        if parsed_key.key_type == KeyType.MOTTO and parsed_key.motto:
            motto_shifts = self._extract_motto_shifts(parsed_key.motto, lang)

        p = start_pos
        result_chars: List[str] = []

        for char in data:
            shifted = False

            if lang in ("auto", "en"):
                if char in self.EN_LOWER:
                    k = parsed_key.get_shift(p, self.en_len, motto_shifts)
                    idx = (self.EN_LOWER.index(char) + k) % self.en_len
                    result_chars.append(self.EN_LOWER[idx])
                    shifted = True
                elif char in self.EN_UPPER:
                    k = parsed_key.get_shift(p, self.en_len, motto_shifts)
                    idx = (self.EN_UPPER.index(char) + k) % self.en_len
                    result_chars.append(self.EN_UPPER[idx])
                    shifted = True

            if not shifted and lang in ("auto", "uk"):
                if char in self.UK_LOWER:
                    k = parsed_key.get_shift(p, self.uk_len, motto_shifts)
                    idx = (self.UK_LOWER.index(char) + k) % self.uk_len
                    result_chars.append(self.UK_LOWER[idx])
                    shifted = True
                elif char in self.UK_UPPER:
                    k = parsed_key.get_shift(p, self.uk_len, motto_shifts)
                    idx = (self.UK_UPPER.index(char) + k) % self.uk_len
                    result_chars.append(self.UK_UPPER[idx])
                    shifted = True

            if shifted:
                p += 1
            else:
                result_chars.append(char)
                if not letter_only:
                    p += 1

        return "".join(result_chars)

    def decrypt(
        self,
        data: str,
        key: Any,
        lang: str = "auto",
        letter_only: bool = True,
        start_pos: int = 0,
    ) -> str:
        if not self.validate_data(data):
            raise TypeError("Дані для розшифрування повинні бути рядком (str).")
        if not self.validate_key(key):
            raise ValueError(f"Невалідний ключ Тритеміуса: {key}")

        parsed_key = TrithemiusKey.from_any(key)
        motto_shifts: Optional[List[int]] = None
        if parsed_key.key_type == KeyType.MOTTO and parsed_key.motto:
            motto_shifts = self._extract_motto_shifts(parsed_key.motto, lang)

        p = start_pos
        result_chars: List[str] = []

        for char in data:
            shifted = False

            if lang in ("auto", "en"):
                if char in self.EN_LOWER:
                    k = parsed_key.get_shift(p, self.en_len, motto_shifts)
                    idx = (self.EN_LOWER.index(char) + self.en_len - (k % self.en_len)) % self.en_len
                    result_chars.append(self.EN_LOWER[idx])
                    shifted = True
                elif char in self.EN_UPPER:
                    k = parsed_key.get_shift(p, self.en_len, motto_shifts)
                    idx = (self.EN_UPPER.index(char) + self.en_len - (k % self.en_len)) % self.en_len
                    result_chars.append(self.EN_UPPER[idx])
                    shifted = True

            if not shifted and lang in ("auto", "uk"):
                if char in self.UK_LOWER:
                    k = parsed_key.get_shift(p, self.uk_len, motto_shifts)
                    idx = (self.UK_LOWER.index(char) + self.uk_len - (k % self.uk_len)) % self.uk_len
                    result_chars.append(self.UK_LOWER[idx])
                    shifted = True
                elif char in self.UK_UPPER:
                    k = parsed_key.get_shift(p, self.uk_len, motto_shifts)
                    idx = (self.UK_UPPER.index(char) + self.uk_len - (k % self.uk_len)) % self.uk_len
                    result_chars.append(self.UK_UPPER[idx])
                    shifted = True

            if shifted:
                p += 1
            else:
                result_chars.append(char)
                if not letter_only:
                    p += 1

        return "".join(result_chars)


class BinaryTrithemiusCipher(BinaryCaesarCipher):
    def validate_key(self, key: Any) -> bool:
        if isinstance(key, (bytes, bytearray)):
            return len(key) > 0
        return TrithemiusKey.validate(key)

    def _get_shift_func(self, key: Any):
        if isinstance(key, (bytes, bytearray)):
            byte_key = bytes(key)
            l = len(byte_key)
            return lambda p: byte_key[p % l]

        parsed = TrithemiusKey.from_any(key)
        if parsed.key_type == KeyType.MOTTO and parsed.motto:
            raw_bytes = parsed.motto.encode("utf-8")
            l = len(raw_bytes)
            return lambda p: raw_bytes[p % l]
        elif parsed.key_type == KeyType.LINEAR:
            a, b = parsed.linear_coeffs  # type: ignore
            return lambda p: (a * p + b) % 256
        elif parsed.key_type == KeyType.NON_LINEAR:
            a, b, c = parsed.nonlinear_coeffs  # type: ignore
            return lambda p: (a * (p ** 2) + b * p + c) % 256
        return lambda p: 0

    def encrypt(self, data: bytes, key: Any) -> bytes:
        if not self.validate_data(data):
            raise TypeError("Дані повинні бути байтами (bytes або bytearray).")
        if not self.validate_key(key):
            raise ValueError(f"Невалідний двійковий ключ Тритеміуса: {key}")

        shift_fn = self._get_shift_func(key)
        return bytes((b + shift_fn(i)) % 256 for i, b in enumerate(data))

    def decrypt(self, data: bytes, key: Any) -> bytes:
        if not self.validate_data(data):
            raise TypeError("Дані повинні бути байтами (bytes або bytearray).")
        if not self.validate_key(key):
            raise ValueError(f"Невалідний двійковий ключ Тритеміуса: {key}")

        shift_fn = self._get_shift_func(key)
        return bytes((b - shift_fn(i)) % 256 for i, b in enumerate(data))


@dataclass
class AttackCandidate:
    key_type: KeyType
    key: TrithemiusKey
    description: str
    confidence: float
    verified: bool


@dataclass
class AttackResult:
    success: bool
    primary_candidate: Optional[AttackCandidate]
    all_candidates: List[AttackCandidate]
    shifts: List[int]
    total_letters_analyzed: int
    alphabet_size: int
    language: str
    explanation: str


class TrithemiusKnownPlaintextAttack:
    def __init__(self, cipher: Optional[TrithemiusCipher] = None):
        self.cipher = cipher or TrithemiusCipher()

    def attack(
        self,
        plaintext: str,
        ciphertext: str,
        lang: str = "auto",
        letter_only: bool = True,
    ) -> AttackResult:
        if not isinstance(plaintext, str) or not isinstance(ciphertext, str):
            raise TypeError("Вхідні тексти мають бути рядками.")

        if not plaintext or not ciphertext:
            raise ValueError("Тексти для атаки не можуть бути порожніми.")

        uk_count = sum(1 for c in plaintext if c in self.cipher.UK_LOWER or c in self.cipher.UK_UPPER)
        en_count = sum(1 for c in plaintext if c in self.cipher.EN_LOWER or c in self.cipher.EN_UPPER)

        target_lang = lang
        if target_lang == "auto":
            target_lang = "uk" if uk_count >= en_count else "en"

        alphabet = self.cipher.UK_LOWER if target_lang == "uk" else self.cipher.EN_LOWER
        alphabet_upper = self.cipher.UK_UPPER if target_lang == "uk" else self.cipher.EN_UPPER
        n = len(alphabet)

        res = self._run_attack_mode(plaintext, ciphertext, target_lang, alphabet, alphabet_upper, n, letter_only)
        if not res.success and letter_only is True:
            alt_res = self._run_attack_mode(plaintext, ciphertext, target_lang, alphabet, alphabet_upper, n, letter_only=False)
            if alt_res.success:
                return alt_res
        return res

    def _run_attack_mode(
        self,
        plaintext: str,
        ciphertext: str,
        lang: str,
        alphabet: str,
        alphabet_upper: str,
        n: int,
        letter_only: bool,
    ) -> AttackResult:
        min_len = min(len(plaintext), len(ciphertext))
        p = 0
        shifts: List[int] = []
        positions: List[int] = []

        for i in range(min_len):
            cp = plaintext[i]
            cc = ciphertext[i]

            is_letter = False
            x = -1
            y = -1

            if cp in alphabet and cc in alphabet:
                x = alphabet.index(cp)
                y = alphabet.index(cc)
                is_letter = True
            elif cp in alphabet_upper and cc in alphabet_upper:
                x = alphabet_upper.index(cp)
                y = alphabet_upper.index(cc)
                is_letter = True

            if is_letter:
                k_val = (y - x) % n
                shifts.append(k_val)
                positions.append(p)
                p += 1
            else:
                if not letter_only:
                    p += 1

        if not shifts:
            return AttackResult(
                success=False,
                primary_candidate=None,
                all_candidates=[],
                shifts=[],
                total_letters_analyzed=0,
                alphabet_size=n,
                language=lang,
                explanation="Не знайдено спільних літер відповідного алфавіту для аналізу.",
            )

        m = len(shifts)
        candidates: List[AttackCandidate] = []

        linear_candidate = self._check_linear(positions, shifts, n, plaintext, ciphertext, lang, letter_only)
        if linear_candidate:
            candidates.append(linear_candidate)

        nonlinear_candidate = self._check_nonlinear(positions, shifts, n, plaintext, ciphertext, lang, letter_only)
        if nonlinear_candidate:
            candidates.append(nonlinear_candidate)

        motto_candidate = self._check_motto(shifts, alphabet, n, plaintext, ciphertext, lang, letter_only)
        if motto_candidate:
            candidates.append(motto_candidate)

        candidates.sort(key=lambda c: (1 if c.verified else 0, c.confidence), reverse=True)

        primary = candidates[0] if candidates else None
        success = bool(primary and primary.verified)

        if success and primary:
            expl = (
                f"Тип знайденого ключа: {primary.key.formula_display()}\n"
                f"Впевненість: {primary.confidence * 100:.1f}%\n"
                f"Проаналізовано літер: {m} (алфавіт n = {n}).\n"
                f"Верифікація: розшифрований текст повністю відповідає відкритому."
            )
        else:
            expl = f"Ключ не вдалося однозначно визначити. Проаналізовано {m} літер."

        return AttackResult(
            success=success,
            primary_candidate=primary,
            all_candidates=candidates,
            shifts=shifts,
            total_letters_analyzed=m,
            alphabet_size=n,
            language=lang,
            explanation=expl,
        )

    def _check_linear(
        self,
        positions: List[int],
        shifts: List[int],
        n: int,
        plaintext: str,
        ciphertext: str,
        lang: str,
        letter_only: bool,
    ) -> Optional[AttackCandidate]:
        m = len(shifts)
        if m < 2:
            return None

        p0 = positions[0]
        k0 = shifts[0]

        found_a: Optional[int] = None
        found_b: Optional[int] = None

        for a in range(n):
            b = (k0 - a * p0) % n
            matches = True
            for p_idx, k_idx in zip(positions, shifts):
                if (a * p_idx + b) % n != k_idx:
                    matches = False
                    break
            if matches:
                found_a = a
                found_b = b
                break

        if found_a is not None and found_b is not None:
            key = TrithemiusKey.linear(found_a, found_b)
            test_enc = self.cipher.encrypt(plaintext, key, lang=lang, letter_only=letter_only)
            verified = (test_enc == ciphertext)
            confidence = 1.0 if m >= 3 else 0.9
            return AttackCandidate(
                key_type=KeyType.LINEAR,
                key=key,
                description=f"Лінійний ключ: k = {found_a}·p + {found_b}",
                confidence=confidence,
                verified=verified,
            )
        return None

    def _check_nonlinear(
        self,
        positions: List[int],
        shifts: List[int],
        n: int,
        plaintext: str,
        ciphertext: str,
        lang: str,
        letter_only: bool,
    ) -> Optional[AttackCandidate]:
        m = len(shifts)
        if m < 3:
            return None

        p0, p1, p2 = positions[0], positions[1], positions[2]
        k0, k1, k2 = shifts[0], shifts[1], shifts[2]

        found_a, found_b, found_c = None, None, None

        for a in range(1, n):
            for b in range(n):
                c = (k0 - a * (p0 ** 2) - b * p0) % n
                if (a * (p1 ** 2) + b * p1 + c) % n != k1:
                    continue
                if (a * (p2 ** 2) + b * p2 + c) % n != k2:
                    continue

                matches = True
                for p_idx, k_idx in zip(positions, shifts):
                    if (a * (p_idx ** 2) + b * p_idx + c) % n != k_idx:
                        matches = False
                        break
                if matches:
                    found_a, found_b, found_c = a, b, c
                    break
            if found_a is not None:
                break

        if found_a is not None and found_b is not None and found_c is not None:
            key = TrithemiusKey.non_linear(found_a, found_b, found_c)
            test_enc = self.cipher.encrypt(plaintext, key, lang=lang, letter_only=letter_only)
            verified = (test_enc == ciphertext)
            confidence = 1.0 if m >= 4 else 0.85
            return AttackCandidate(
                key_type=KeyType.NON_LINEAR,
                key=key,
                description=f"Нелінійний ключ: k = {found_a}·p² + {found_b}·p + {found_c}",
                confidence=confidence,
                verified=verified,
            )
        return None

    def _check_motto(
        self,
        shifts: List[int],
        alphabet: str,
        n: int,
        plaintext: str,
        ciphertext: str,
        lang: str,
        letter_only: bool,
    ) -> Optional[AttackCandidate]:
        m = len(shifts)
        if m == 0:
            return None

        motto_chars = [alphabet[k] for k in shifts]

        detected_period = m
        for L in range(1, m):
            is_period = True
            for i in range(m):
                if shifts[i] != shifts[i % L]:
                    is_period = False
                    break
            if is_period:
                detected_period = L
                break

        reconstructed_motto = "".join(motto_chars[:detected_period])
        key = TrithemiusKey.from_motto(reconstructed_motto)

        test_enc = self.cipher.encrypt(plaintext, key, lang=lang, letter_only=letter_only)
        verified = (test_enc == ciphertext)

        confidence = 0.95 if detected_period < m else 0.7
        return AttackCandidate(
            key_type=KeyType.MOTTO,
            key=key,
            description=f"Гасло: «{reconstructed_motto}» (довжина {detected_period})",
            confidence=confidence,
            verified=verified,
        )


class BinaryTrithemiusAttack:
    def attack(self, original_data: bytes, encrypted_data: bytes) -> Optional[TrithemiusKey]:
        min_len = min(len(original_data), len(encrypted_data))
        if min_len < 2:
            return None

        shifts = [(encrypted_data[i] - original_data[i]) % 256 for i in range(min_len)]

        k0, k1 = shifts[0], shifts[1]
        b = k0
        a = (k1 - k0) % 256
        if all((a * i + b) % 256 == shifts[i] for i in range(min_len)):
            return TrithemiusKey.linear(a, b)

        if min_len >= 3:
            k2 = shifts[2]
            c = k0
            for cand_a in range(1, 256):
                cand_b = (k1 - c - cand_a) % 256
                if (cand_a * 4 + cand_b * 2 + c) % 256 == k2:
                    if all((cand_a * (i ** 2) + cand_b * i + c) % 256 == shifts[i] for i in range(min_len)):
                        return TrithemiusKey.non_linear(cand_a, cand_b, c)

        for L in range(1, min_len):
            if all(shifts[i] == shifts[i % L] for i in range(min_len)):
                try:
                    motto_str = bytes(shifts[:L]).decode("utf-8")
                    return TrithemiusKey.from_motto(motto_str)
                except UnicodeDecodeError:
                    return None
        return None
