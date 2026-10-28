from __future__ import annotations

import os
import re
import uuid
from typing import Any, Dict, Optional, Tuple, Type

import clr  # noqa: F401  # pythonnet: завантажує .NET Framework

from System import Array, ArgumentException, BitConverter, Byte, Convert, FormatException
from System.IO import FileAccess, FileMode, FileStream, IOException, MemoryStream
from System.Security.Cryptography import (
    AesCryptoServiceProvider,
    CipherMode,
    CryptographicException,
    CryptoStream,
    CryptoStreamMode,
    DES,
    DESCryptoServiceProvider,
    PaddingMode,
    TripleDES,
    TripleDESCryptoServiceProvider,
)
from System.Text import DecoderFallback, DecoderFallbackException, EncoderFallback, EncoderFallbackException
from System.Text import Encoding, UTF8Encoding

from pr1.cipher import BaseCipher, CipherEncDec

MODES = ("CBC", "ECB", "CFB", "OFB", "CTS")
PADDINGS = ("PKCS7", "ANSIX923", "ISO10126", "Zeros", "None")
KEY_FORMATS = ("ASCII", "HEX")
OUTPUT_FORMATS = ("Base64", "HEX")

# Строгі кодування: стандартний ASCIIEncoding мовчки замінює не-ASCII символи на '?'
ASCII = Encoding.GetEncoding("us-ascii", EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback)
UTF8 = UTF8Encoding(False, True)

NET_ERRORS = (CryptographicException, ArgumentException, IOException)


class SymmetricCipherError(ValueError):
    pass


def ensure_net_string(text: Any, what: str = "Текст") -> str:
    # pythonnet аварійно завершує процес на рядках з одиночними сурогатами
    if not isinstance(text, str):
        raise TypeError(f"{what} має бути рядком (str).")
    try:
        text.encode("utf-16-le")
    except UnicodeEncodeError:
        raise SymmetricCipherError(f"{what} містить некоректні символи Unicode (одиночні сурогати).") from None
    return text


def parse_hex(text: str, what: str = "HEX-рядок") -> bytes:
    cleaned = re.sub(r"[\s\-:]", "", ensure_net_string(text, what))
    if not cleaned:
        raise SymmetricCipherError(f"{what} порожній.")
    if not re.fullmatch(r"[0-9A-Fa-f]+", cleaned):
        raise SymmetricCipherError(f"{what} містить символи, що не є HEX-цифрами (0-9, A-F).")
    if len(cleaned) % 2:
        raise SymmetricCipherError(f"{what} має непарну кількість HEX-цифр ({len(cleaned)}).")
    return bytes.fromhex(cleaned)


def to_hex(data: bytes) -> str:
    return BitConverter.ToString(bytes(data)) if data else ""


def text_to_bytes(text: str, fmt: str = "ASCII", what: str = "Ключ") -> bytes:
    if fmt == "HEX":
        return parse_hex(text, what)
    if fmt != "ASCII":
        raise SymmetricCipherError(f"Невідомий формат: {fmt!r}. Доступні: {', '.join(KEY_FORMATS)}.")
    if not ensure_net_string(text, what):
        raise SymmetricCipherError(f"{what} порожній.")
    try:
        return bytes(ASCII.GetBytes(text))
    except EncoderFallbackException:
        raise SymmetricCipherError(f"{what} у форматі ASCII може містити лише латиницю, цифри та знаки.") from None


def encode_output(data: bytes, fmt: str = "Base64") -> str:
    if fmt == "Base64":
        return Convert.ToBase64String(bytes(data))
    if fmt == "HEX":
        return to_hex(data)
    raise SymmetricCipherError(f"Невідомий формат: {fmt!r}. Доступні: {', '.join(OUTPUT_FORMATS)}.")


def decode_input(text: str, fmt: str = "Base64") -> bytes:
    text = ensure_net_string(text, "Шифротекст").strip()
    if not text:
        raise SymmetricCipherError("Шифротекст порожній.")
    if fmt == "HEX":
        return parse_hex(text, "Шифротекст")
    if fmt != "Base64":
        raise SymmetricCipherError(f"Невідомий формат: {fmt!r}. Доступні: {', '.join(OUTPUT_FORMATS)}.")
    try:
        return bytes(Convert.FromBase64String(re.sub(r"\s", "", text)))
    except FormatException:
        raise SymmetricCipherError("Шифротекст не є коректним рядком Base64.") from None


def _close(*streams):
    # CryptoStream при Dispose повторно кидає помилку, якщо дані пошкоджені
    for stream in streams:
        if stream is not None:
            try:
                stream.Dispose()
            except Exception:
                pass


class NetSymmetricCipher(CipherEncDec, BaseCipher):
    NAME = ""
    PROVIDER: Any = None

    def __init__(self, mode: str = "CBC", padding: str = "PKCS7"):
        self.provider = self.PROVIDER()
        self.mode = mode
        self.padding = padding

    @property
    def mode(self) -> str:
        return self._mode

    @mode.setter
    def mode(self, value: str):
        if value not in MODES:
            raise SymmetricCipherError(f"Невідомий режим шифрування: {value!r}. Доступні: {', '.join(MODES)}.")
        self._mode = value

    @property
    def padding(self) -> str:
        return self._padding

    @padding.setter
    def padding(self, value: str):
        if value not in PADDINGS:
            raise SymmetricCipherError(f"Невідомий режим доповнення: {value!r}. Доступні: {', '.join(PADDINGS)}.")
        self._padding = value

    @property
    def block_size(self) -> int:
        return self.provider.BlockSize // 8

    @property
    def key_sizes(self) -> Tuple[int, ...]:
        sizes = []
        for ks in self.provider.LegalKeySizes:
            sizes.extend(range(ks.MinSize, ks.MaxSize + 1, ks.SkipSize or ks.MaxSize))
        return tuple(bits // 8 for bits in sizes)

    @property
    def needs_iv(self) -> bool:
        return self.mode != "ECB"

    def validate_key(self, key: Any) -> bool:
        try:
            self._check_key(key)
            return True
        except (TypeError, SymmetricCipherError):
            return False

    def validate_iv(self, iv: Any) -> bool:
        try:
            self._check_iv(iv)
            return True
        except (TypeError, SymmetricCipherError):
            return False

    def validate_data(self, data: Any) -> bool:
        return isinstance(data, (str, bytes, bytearray)) and len(data) > 0

    def _check_key(self, key: Any):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Ключ має бути послідовністю байтів (bytes).")
        if len(key) not in self.key_sizes:
            sizes = " / ".join(map(str, self.key_sizes))
            raise SymmetricCipherError(f"Ключ {self.NAME} має бути {sizes} байт, а отримано {len(key)}.")
        self._check_weak_key(bytes(key))

    def _check_weak_key(self, key: bytes):
        pass

    def _check_iv(self, iv: Any):
        if not self.needs_iv:
            return
        if iv is None:
            raise SymmetricCipherError(f"Режим {self.mode} потребує вектор ініціалізації (IV).")
        if not isinstance(iv, (bytes, bytearray)):
            raise TypeError("IV має бути послідовністю байтів (bytes).")
        if len(iv) != self.block_size:
            raise SymmetricCipherError(f"IV для {self.NAME} має бути {self.block_size} байт, а отримано {len(iv)}.")

    def _check_block_aligned(self, length: int, what: str):
        if length % self.block_size:
            raise SymmetricCipherError(f"{what} має бути кратна {self.block_size} байт, а маємо {length}.")

    def _translate(self, exc: Exception, decrypting: bool = False) -> SymmetricCipherError:
        if self.mode in ("OFB", "CTS"):
            return SymmetricCipherError(f"Режим {self.mode} не підтримується провайдером {self.PROVIDER.__name__} у .NET Framework.")
        if decrypting:
            return SymmetricCipherError("Не вдалося розшифрувати: невірний ключ, IV, режим чи доповнення, або дані пошкоджені.")
        return SymmetricCipherError(f"Помилка криптопровайдера .NET: {exc.Message if hasattr(exc, 'Message') else exc}")

    def _configure(self, key: bytes, iv: Optional[bytes]):
        self._check_key(key)
        self._check_iv(iv)
        try:
            self.provider.Mode = getattr(CipherMode, self.mode)
            self.provider.Padding = getattr(PaddingMode, self.padding)
            if self.mode == "CFB":
                self.provider.FeedbackSize = 8
            self.provider.Key = bytes(key)
            if self.needs_iv:
                self.provider.IV = bytes(iv)
        except NET_ERRORS as e:
            raise self._translate(e) from None

    def create_encryptor(self, key: bytes, iv: Optional[bytes] = None):
        self._configure(key, iv)
        try:
            return self.provider.CreateEncryptor()
        except NET_ERRORS as e:
            raise self._translate(e) from None

    def create_decryptor(self, key: bytes, iv: Optional[bytes] = None):
        self._configure(key, iv)
        try:
            return self.provider.CreateDecryptor()
        except NET_ERRORS as e:
            raise self._translate(e) from None

    def generate_key(self) -> bytes:
        self.provider.GenerateKey()
        return bytes(self.provider.Key)

    def generate_iv(self) -> bytes:
        self.provider.GenerateIV()
        return bytes(self.provider.IV)

    def split_iv(self, blob: bytes) -> Tuple[bytes, bytes]:
        if len(blob) <= self.block_size:
            raise SymmetricCipherError(
                f"Шифротекст закороткий: очікується IV ({self.block_size} байт) і щонайменше один блок даних."
            )
        return blob[:self.block_size], blob[self.block_size:]

    def encrypt_bytes(self, data: bytes, key: bytes, iv: Optional[bytes] = None) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Дані для шифрування мають бути байтами (bytes).")
        if not data:
            raise SymmetricCipherError("Немає даних для шифрування.")
        if self.padding == "None":
            self._check_block_aligned(len(data), "Без доповнення (Padding = None) довжина даних")
        encryptor = self.create_encryptor(key, iv)
        target = MemoryStream()
        crypto = CryptoStream(target, encryptor, CryptoStreamMode.Write)
        try:
            crypto.Write(bytes(data), 0, len(data))
            crypto.FlushFinalBlock()
            return bytes(target.ToArray())
        except NET_ERRORS as e:
            raise self._translate(e) from None
        finally:
            _close(crypto, target)

    def decrypt_bytes(self, data: bytes, key: bytes, iv: Optional[bytes] = None) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Шифротекст має бути байтами (bytes).")
        if not data:
            raise SymmetricCipherError("Шифротекст порожній.")
        self._check_block_aligned(len(data), "Довжина шифротексту")
        decryptor = self.create_decryptor(key, iv)
        source = MemoryStream(bytes(data))
        crypto = CryptoStream(source, decryptor, CryptoStreamMode.Read)
        target = MemoryStream()
        try:
            crypto.CopyTo(target)
            return bytes(target.ToArray())
        except NET_ERRORS as e:
            raise self._translate(e, decrypting=True) from None
        finally:
            _close(crypto, source, target)

    def encrypt(self, data: Any, key: bytes, iv: Optional[bytes] = None) -> bytes:
        if isinstance(data, str):
            data = bytes(UTF8.GetBytes(ensure_net_string(data))) if data else b""
        return self.encrypt_bytes(data, key, iv)

    def decrypt(self, data: bytes, key: bytes, iv: Optional[bytes] = None) -> str:
        plain = self.decrypt_bytes(data, key, iv)
        if self.padding == "Zeros":
            plain = plain.rstrip(b"\x00")
        try:
            return UTF8.GetString(plain) if plain else ""
        except DecoderFallbackException:
            raise SymmetricCipherError(
                "Розшифровані байти не є текстом UTF-8: ймовірно, невірний ключ, IV або режим."
            ) from None

    @staticmethod
    def _check_paths(src: Any, dst: Any) -> Tuple[str, str]:
        for path, what in ((src, "вхідного"), (dst, "вихідного")):
            if not isinstance(path, (str, os.PathLike)) or not os.fspath(path).strip():
                raise SymmetricCipherError(f"Не задано шлях {what} файлу.")
            ensure_net_string(os.fspath(path), f"Шлях {what} файлу")
        src, dst = os.path.abspath(os.fspath(src)), os.path.abspath(os.fspath(dst))
        if not os.path.isfile(src):
            raise SymmetricCipherError(f"Вхідний файл не знайдено:\n{src}")
        if not os.path.isdir(os.path.dirname(dst)):
            raise SymmetricCipherError(f"Тека для вихідного файлу не існує:\n{os.path.dirname(dst)}")
        if os.path.normcase(src) == os.path.normcase(dst) or (os.path.exists(dst) and os.path.samefile(src, dst)):
            raise SymmetricCipherError("Вихідний файл не може збігатися з вхідним.")
        return src, dst

    def encrypt_file(self, src: str, dst: str, key: bytes, iv: Optional[bytes] = None, embed_iv: bool = False) -> int:
        return self._process_file(src, dst, key, iv, embed_iv, encrypting=True)

    def decrypt_file(self, src: str, dst: str, key: bytes, iv: Optional[bytes] = None, embed_iv: bool = False) -> int:
        return self._process_file(src, dst, key, iv, embed_iv, encrypting=False)

    def _process_file(self, src, dst, key, iv, embed_iv: bool, encrypting: bool) -> int:
        src, dst = self._check_paths(src, dst)
        size = os.path.getsize(src)
        if size == 0:
            raise SymmetricCipherError("Вхідний файл порожній.")
        embed_iv = embed_iv and self.needs_iv
        if encrypting and self.padding == "None":
            self._check_block_aligned(size, "Без доповнення (Padding = None) довжина файлу")
        if not encrypting:
            header = self.block_size if embed_iv else 0
            if size <= header:
                raise SymmetricCipherError("Файл закороткий: у ньому немає IV та зашифрованих даних.")
            self._check_block_aligned(size - header, "Довжина зашифрованих даних у файлі")

        # Результат пишеться у тимчасовий файл, щоб при помилці не лишився частково розшифрований вміст
        tmp = f"{dst}.{uuid.uuid4().hex}.tmp"
        fs_in = fs_out = crypto = None
        try:
            fs_in = FileStream(src, FileMode.Open, FileAccess.Read)
            if not encrypting and embed_iv:
                buffer = Array[Byte](self.block_size)
                fs_in.Read(buffer, 0, self.block_size)
                iv = bytes(buffer)
            fs_out = FileStream(tmp, FileMode.CreateNew, FileAccess.Write)
            if encrypting:
                encryptor = self.create_encryptor(key, iv)
                if embed_iv:
                    fs_out.Write(bytes(iv), 0, len(iv))
                crypto = CryptoStream(fs_out, encryptor, CryptoStreamMode.Write)
                fs_in.CopyTo(crypto)
                crypto.FlushFinalBlock()
            else:
                crypto = CryptoStream(fs_in, self.create_decryptor(key, iv), CryptoStreamMode.Read)
                crypto.CopyTo(fs_out)
            fs_out.Flush()
        except NET_ERRORS as e:
            _close(crypto, fs_out, fs_in)
            self._remove(tmp)
            if isinstance(e, IOException):
                raise SymmetricCipherError(f"Помилка роботи з файлом: {e.Message}") from None
            raise self._translate(e, decrypting=not encrypting) from None
        except BaseException:
            _close(crypto, fs_out, fs_in)
            self._remove(tmp)
            raise
        _close(crypto, fs_out, fs_in)
        try:
            os.replace(tmp, dst)
        except OSError as e:
            self._remove(tmp)
            raise SymmetricCipherError(f"Не вдалося записати вихідний файл: {e}") from None
        return os.path.getsize(dst)

    @staticmethod
    def _remove(path: str):
        try:
            os.remove(path)
        except OSError:
            pass


class DESCipher(NetSymmetricCipher):
    NAME = "DES"
    PROVIDER = DESCryptoServiceProvider

    def _check_weak_key(self, key: bytes):
        if DES.IsWeakKey(key):
            raise SymmetricCipherError("Ключ є слабким ключем DES: шифрування збігається з розшифруванням.")
        if DES.IsSemiWeakKey(key):
            raise SymmetricCipherError("Ключ є напівслабким ключем DES: його пара розшифровує його шифротекст.")


class TripleDESCipher(NetSymmetricCipher):
    NAME = "TripleDES"
    PROVIDER = TripleDESCryptoServiceProvider

    def _check_weak_key(self, key: bytes):
        if TripleDES.IsWeakKey(key):
            raise SymmetricCipherError("Ключ TripleDES вироджується в одинарний DES (K1 = K2 або K2 = K3).")


class AESCipher(NetSymmetricCipher):
    NAME = "AES"
    PROVIDER = AesCryptoServiceProvider


CIPHERS: Dict[str, Type[NetSymmetricCipher]] = {
    "DES": DESCipher,
    "TripleDES": TripleDESCipher,
    "AES": AESCipher,
}


def create_cipher(name: str, mode: str = "CBC", padding: str = "PKCS7") -> NetSymmetricCipher:
    if name not in CIPHERS:
        raise SymmetricCipherError(f"Невідомий шифр: {name!r}. Доступні: {', '.join(CIPHERS)}.")
    return CIPHERS[name](mode, padding)
