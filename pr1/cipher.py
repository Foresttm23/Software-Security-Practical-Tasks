from abc import ABC, abstractmethod
from typing import Any, List, Tuple


class BaseCipher(ABC):
    @abstractmethod
    def validate_key(self, key: Any) -> bool:
        """Перевірка валідності ключа."""
        pass

    @abstractmethod
    def validate_data(self, data: Any) -> bool:
        """Перевірка валідності вхідних даних."""
        pass

    @abstractmethod
    def encrypt(self, data: Any, key: Any) -> Any:
        """Шифрування даних за допомогою ключа."""
        pass

    @abstractmethod
    def decrypt(self, data: Any, key: Any) -> Any:
        """Розшифрування даних за допомогою ключа."""
        pass

class CipherEncDec:
    def validate_key(self, key: Any) -> bool:
        if isinstance(key, bool):
            return False
        if isinstance(key, int):
            return True
        if isinstance(key, str):
            try:
                int(key)
                return True
            except ValueError:
                return False
        return False

class CaesarCipher(CipherEncDec, BaseCipher):
    EN_LOWER = "abcdefghijklmnopqrstuvwxyz"
    EN_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    UK_LOWER = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"
    UK_UPPER = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"

    def __init__(self):
        self.en_len = len(self.EN_LOWER)
        self.uk_len = len(self.UK_LOWER)

    def validate_data(self, data: Any) -> bool:
        return isinstance(data, str)

    def _shift_char(self, char: str, key: int, lang: str = "auto") -> str:
        """y = (x + k) mod n"""
        if lang in ("auto", "en"):
            if char in self.EN_LOWER:
                idx = self.EN_LOWER.index(char)
                return self.EN_LOWER[(idx + key) % self.en_len]
            if char in self.EN_UPPER:
                idx = self.EN_UPPER.index(char)
                return self.EN_UPPER[(idx + key) % self.en_len]

        if lang in ("auto", "uk"):
            if char in self.UK_LOWER:
                idx = self.UK_LOWER.index(char)
                return self.UK_LOWER[(idx + key) % self.uk_len]
            if char in self.UK_UPPER:
                idx = self.UK_UPPER.index(char)
                return self.UK_UPPER[(idx + key) % self.uk_len]

        return char

    def encrypt(self, data: str, key: Any, lang: str = "auto") -> str:
        """y = (x + k) mod n"""
        if not self.validate_data(data):
            raise TypeError("Дані для шифрування повинні бути рядком (str).")
        if not self.validate_key(key):
            raise ValueError(f"Невалідний ключ: {key}. Ключ має бути цілим числом.")

        int_key = int(key)
        return "".join(self._shift_char(c, int_key, lang) for c in data)

    def decrypt(self, data: str, key: Any, lang: str = "auto") -> str:
        """x = (y - k) mod n"""
        if not self.validate_data(data):
            raise TypeError("Дані для розшифрування повинні бути рядком (str).")
        if not self.validate_key(key):
            raise ValueError(f"Невалідний ключ: {key}. Ключ має бути цілим числом.")

        int_key = int(key)
        return "".join(self._shift_char(c, -int_key, lang) for c in data)


class BinaryCaesarCipher(CipherEncDec, BaseCipher):
    """y = (b + k) mod 256"""

    def validate_data(self, data: Any) -> bool:
        return isinstance(data, (bytes, bytearray))

    def encrypt(self, data: bytes, key: Any) -> bytes:
        if not self.validate_data(data):
            raise TypeError("Дані повинні бути байтами (bytes або bytearray).")
        if not self.validate_key(key):
            raise ValueError(f"Невалідний ключ: {key}. Ключ має бути цілим числом.")

        int_key = int(key) % 256
        return bytes((b + int_key) % 256 for b in data)

    def decrypt(self, data: bytes, key: Any) -> bytes:
        if not self.validate_data(data):
            raise TypeError("Дані повинні бути байтами (bytes або bytearray).")
        if not self.validate_key(key):
            raise ValueError(f"Невалідний ключ: {key}. Ключ має бути цілим числом.")

        int_key = int(key) % 256
        return bytes((b - int_key) % 256 for b in data)


class CaesarBruteForce:
    COMMON_EN = set("etaoinshrdlu")
    COMMON_UK = set("оаинівтесрлк")

    def __init__(self, cipher: CaesarCipher | None = None):
        self.cipher = cipher or CaesarCipher()

    def attack(self, ciphertext: str, lang: str = "auto") -> List[Tuple[int, str, float]]:
        if not self.cipher.validate_data(ciphertext):
            raise TypeError("Шифротекст має бути рядком.")

        max_keys = self.cipher.uk_len if lang == "uk" else (self.cipher.en_len if lang == "en" else max(self.cipher.en_len, self.cipher.uk_len))

        results = []
        for key in range(1, max_keys):
            decrypted = self.cipher.decrypt(ciphertext, key, lang=lang)
            score = self._calculate_score(decrypted, lang)
            results.append((key, decrypted, score))

        results.sort(key=lambda x: x[2], reverse=True)
        return results

    def _calculate_score(self, text: str, lang: str) -> float:
        if not text:
            return 0.0
        lower = text.lower()
        common_set = self.COMMON_UK if lang == "uk" else (self.COMMON_EN if lang == "en" else self.COMMON_EN | self.COMMON_UK)
        matches = sum(1 for c in lower if c in common_set)
        spaces = lower.count(" ") * 2
        return (matches + spaces) / len(text)
