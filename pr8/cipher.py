from __future__ import annotations

import re
from typing import Any, Optional, Tuple

import clr  # noqa: F401  # pythonnet: завантажує .NET Framework

from System import Convert, FormatException
from System import Exception as NetException
from System.Security.Cryptography import (
    DSACryptoServiceProvider,
    RSACryptoServiceProvider,
    SHA1CryptoServiceProvider,
    SHA256CryptoServiceProvider,
    SHA512CryptoServiceProvider,
)

from pr1.cipher import BaseCipher, CipherEncDec
from pr5.cipher import UTF8, SymmetricCipherError, ensure_net_string, parse_hex, to_hex

SIGNATURE_FORMATS = ("HEX", "Base64")
HASH_PROVIDERS = {
    "SHA1": SHA1CryptoServiceProvider,
    "SHA256": SHA256CryptoServiceProvider,
    "SHA512": SHA512CryptoServiceProvider,
}
RSA_SIGN_KEY_SIZES = (512, 1024, 2048, 3072, 4096)
DSA_SIGN_KEY_SIZES = tuple(range(512, 1025, 64))
MAX_MESSAGE_LENGTH = 10_000_000
MAX_XML_LENGTH = 100_000

EXAMPLE_MESSAGE = "Hello world!"

RSA_EXAMPLE_XML = (
    "<RSAKeyValue><Modulus>mJ32CjZjzD2Qw4oRc/3O4xyVBLLPHeXELhIa9kwPhPCERkhuvROalKgfodSgOrVr2K9TgTAMw3Ua4Q9O/vWhJRz"
    "sQPcSEYc5wJuHU9QY0a9jPn7WJQY91uCwfA54GsVYTLo2VI60DEtuES7Dhlj4VK5KemvudEkmHiY8/BfO0XM=</Modulus>"
    "<Exponent>AQAB</Exponent>"
    "<P>z9JDG1Avu9q5LlBNG6NQcxdhZc+HnJsQahjmza/fZb6T/K0tThAjAM18dH2gCCac05oJn2QEyCbtW5RgQ3lgvQ==</P>"
    "<Q>u/9yCtIK1GjfS16K5pNkSqdVZr2QDHbjy0cHiO7LfKBtWugUyN3FCSSUBooF2DmNFvRKDm1mZ4iPP7nMsqYV7w==</Q>"
    "<DP>burHyjIX5+kq4J8XKGMXsvWNlCsZM+pG7nlv5eOyFbmLflZnUbynEeyaOgo6eV8yYHVcIWfebXzpPfGJFzoW+Q==</DP>"
    "<DQ>hZeph6zoyzZW7u0ZEW7NxwsP8flk4qadizdHUHQ4n7A05XOkSXTmbm/SzK7KJnQHIbeo5IWzToFJIkS7BHxnew==</DQ>"
    "<InverseQ>jbhzN1BGEp4rA8njVFoHv8nYoywX0fG0tVoeMkuu+V5St81pD5oY5rz+OMksTxD+scpSF8DnhEewtBPMDOTJDg==</InverseQ>"
    "<D>P2uU7NWBT0RePgPIEO1t5c7g1h0AGKp8hbCcZ7Ff2ZyhOxuqeQQGfrQGwRc8pmjxsg/ZoZu4Ehk93DyiVSz5k3AfGe7vW+Mwk6jM71deo"
    "SyBdKpP1S/cpssOJHY781Tcx8jqqmP/gN19jEUkU7mJcmv4ahkis79THvo/FvAmkJE=</D></RSAKeyValue>"
)
RSA_EXAMPLE_SIGNATURE_HEX = (
    "4725D1135F715C2FCFA2C6E93C839B106F1F8B2481CD599A5062652C39D2B63675D5254377B7400AF85E3338F8023AA53D59AEC014481"
    "5C76FD02E22C0F3D8B976CDCDCF1DE42BAF7D4314C3124B54E4B17B114A6E226001913AE15939584001AA1E98FA81C1F435F0F272DFEE"
    "D1C27476B6F2C3E5A7AF968CAC149892B7A198"
)
RSA_EXAMPLE_SIGNATURE_B64 = (
    "RyXRE19xXC/PosbpPIObEG8fiySBzVmaUGJlLDnStjZ11SVDd7dACvheMzj4AjqlPVmuwBRIFcdv0C4iwPPYuXbNzc8d5CuvfUMUwxJLVOSx"
    "exFKbiJgAZE64Vk5WEABqh6Y+oHB9DXw8nLf7tHCdHa28sPlp6+WjKwUmJK3oZg="
)

DSA_EXAMPLE_PUBLIC_XML = (
    "<DSAKeyValue><P>jmQh1u62F7h3RMkRs+uhoGn4fQMhih8GyZPWmJJHRwcOVxmJC5d5cR0k7PFf0x0+PvkHr+wFSTvB2ZregiasXJ8WnHUvE"
    "cFCHbJ+iRiKQD1Rd75HfN8o8ViqL36Ia6PM1ZwI2Fqyc0zJshoZqg2CQX8cDwO7T/Ogea+S+5bnrrE=</P>"
    "<Q>68r+49IOAxNZNJkG43A5I+Ma9hE=</Q>"
    "<G>g9RWkaYfOs1tOewwxFHZFgN9NFTDz6FW5UWN2bakbfyOOZ2xeveYQ87nJEg5nXv4ZSTo7mxP2AhuL8lFKKmGcPLDgPFwjcWqTAeMTd3x6"
    "zKDb1Ev0N4VTzzHD0GNLfTfdtQpTYuzzifp+gh2rtkmqF29g8DqOgG1uI9pVYfvYF0=</G>"
    "<Y>Q6SrbyDo6/T0n8aZrWowe3YJKgEzEZhT7qAY8nZ2O7CvCIM7Y3M8/9DkddrAosk1X4pSye5bmBTERpDB1+I7TlAqS+sOeUx69UL6OJlRG"
    "Tfdai51g9T/qy7nPqwgY/jBQx4UvPjLIsFaovCjjRDLTje9X8Q2i+5c/OSdHN8/mfQ=</Y>"
    "<J>mpgEUdSn4XqlWugO+TKaF4r7WFQkux4wRPRIJHoL/wBgjIY8oA9Ji8RgVOGgb9TI61ll5BTM4mfR/ucCgMHtoKRbi8dOzOgoj6hdT1BWD"
    "g4vW23t6v8Up3/APn/tO+ZAOaL26rZuscyaJ1Ow</J>"
    "<Seed>U1+1KTe5EGYeuLYQojzYeoTfGnk=</Seed><PgenCounter>Ag==</PgenCounter></DSAKeyValue>"
)
DSA_EXAMPLE_SIGNATURE_B64 = "mxdOkPaZrDdDnl15sEL8GQim6B4/c2fbd2ksc4ByqxOVS7TA1ouXqg=="


class SignatureError(ValueError):
    pass


def message_bytes(message: Any) -> bytes:
    if isinstance(message, (bytes, bytearray)):
        data = bytes(message)
    else:
        try:
            text = ensure_net_string(message, "Повідомлення")
        except SymmetricCipherError as e:
            raise SignatureError(str(e)) from None
        if len(text) > MAX_MESSAGE_LENGTH:
            raise SignatureError(f"Повідомлення занадто довге (понад {MAX_MESSAGE_LENGTH} символів).")
        data = bytes(UTF8.GetBytes(text)) if text else b""
    if not data:
        raise SignatureError("Повідомлення порожнє: немає що підписувати.")
    return data


def compute_hash(data: bytes, algorithm: str = "SHA1") -> bytes:
    if algorithm not in HASH_PROVIDERS:
        raise SignatureError(f"Невідомий геш-алгоритм: {algorithm!r}. Доступні: {', '.join(HASH_PROVIDERS)}.")
    hasher = HASH_PROVIDERS[algorithm]()
    try:
        return bytes(hasher.ComputeHash(bytes(data)))
    finally:
        hasher.Dispose()


def encode_signature(signature: bytes, fmt: str = "HEX") -> str:
    if fmt == "HEX":
        return to_hex(signature).replace("-", "")
    if fmt == "Base64":
        return str(Convert.ToBase64String(bytes(signature)))
    raise SignatureError(f"Невідомий формат підпису: {fmt!r}. Доступні: {', '.join(SIGNATURE_FORMATS)}.")


def decode_signature(text: Any, fmt: str = "HEX") -> bytes:
    try:
        text = ensure_net_string(text, "Підпис").strip()
        if not text:
            raise SignatureError("Підпис порожній: вставте підпис або спочатку підпишіть повідомлення.")
        if fmt == "HEX":
            # Приймаються обидва варіанти: AABB... (StringToByteArray) та AA-BB-... (BitConverter.ToString)
            return parse_hex(text, "Підпис")
    except SymmetricCipherError as e:
        raise SignatureError(str(e)) from None
    if fmt != "Base64":
        raise SignatureError(f"Невідомий формат підпису: {fmt!r}. Доступні: {', '.join(SIGNATURE_FORMATS)}.")
    try:
        return bytes(Convert.FromBase64String(re.sub(r"\s", "", text)))
    except FormatException:
        raise SignatureError("Підпис не є коректним рядком Base64.") from None


class NetSigner(CipherEncDec, BaseCipher):
    NAME = ""
    PROVIDER = None
    XML_TAGS: Tuple[str, ...] = ()
    HASHES: Tuple[str, ...] = ("SHA1",)
    KEY_SIZES: Tuple[int, ...] = ()

    def __init__(self, key_size: Optional[int] = 1024, xml: Optional[str] = None):
        self.provider = None
        if xml is not None:
            self.import_xml(xml)
        elif key_size is not None:
            self.generate(key_size)

    @classmethod
    def _new_provider(cls, key_size: Optional[int] = None):
        provider = cls.PROVIDER(key_size) if key_size else cls.PROVIDER()
        # Ключ живе лише в пам'яті і не зберігається у сховищі ключів Windows
        provider.PersistKeyInCsp = False
        return provider

    @classmethod
    def legal_key_sizes(cls) -> Tuple[int, int, int]:
        provider = cls._new_provider()
        try:
            ks = provider.LegalKeySizes[0]
            return ks.MinSize, ks.MaxSize, ks.SkipSize
        finally:
            provider.Dispose()

    @classmethod
    def check_key_size(cls, key_size: Any) -> int:
        if isinstance(key_size, bool) or not isinstance(key_size, (int, str)):
            raise SignatureError("Розмір ключа має бути цілим числом.")
        text = str(key_size).strip()
        if not re.fullmatch(r"\d{1,6}", text):
            raise SignatureError(f"Розмір ключа має бути цілим додатним числом, а отримано {text[:20]!r}.")
        size = int(text)
        low, high, step = cls.legal_key_sizes()
        if not low <= size <= high or (size - low) % step:
            raise SignatureError(f"Розмір ключа {cls.NAME} має бути від {low} до {high} біт з кроком {step}, а отримано {size}.")
        return size

    def generate(self, key_size: Any = 1024):
        size = self.check_key_size(key_size)
        try:
            self._set_provider(self._new_provider(size))
            self.provider.ExportParameters(True)  # змушує провайдер згенерувати ключ одразу
        except NetException as e:
            raise SignatureError(f"Помилка криптопровайдера .NET: {e.Message.strip()}") from None

    def _set_provider(self, provider):
        if self.provider is not None:
            self.provider.Dispose()
        self.provider = provider

    def _require(self):
        if self.provider is None:
            raise SignatureError(f"Ключ {self.NAME} ще не сформовано: згенеруйте пару ключів або імпортуйте ключ.")
        return self.provider

    @property
    def key_size(self) -> int:
        return self._require().KeySize

    @property
    def has_private(self) -> bool:
        return not self._require().PublicOnly

    @property
    def signature_size(self) -> int:
        raise NotImplementedError

    @classmethod
    def _load_xml(cls, xml: Any):
        try:
            xml = ensure_net_string(xml, "XML ключа").strip()
        except SymmetricCipherError as e:
            raise SignatureError(str(e)) from None
        if not xml:
            raise SignatureError("XML ключа порожній.")
        if len(xml) > MAX_XML_LENGTH:
            raise SignatureError(f"XML ключа занадто довгий (понад {MAX_XML_LENGTH} символів).")
        missing = [tag for tag in cls.XML_TAGS if f"<{tag}>" not in xml]
        if missing:
            other = "RSA" if "<RSAKeyValue>" in xml else "DSA" if "<DSAKeyValue>" in xml else None
            hint = f" Це ключ {other}, а потрібен ключ {cls.NAME}." if other and other != cls.NAME else ""
            raise SignatureError(f"XML не схожий на ключ {cls.NAME}: бракує елементів "
                                 f"{', '.join(f'<{t}>' for t in missing)}.{hint}")
        provider = cls._new_provider()
        try:
            provider.FromXmlString(xml)
        except NetException as e:
            provider.Dispose()
            raise SignatureError(f"Некоректний XML ключа {cls.NAME}: {e.Message.strip()}") from None
        return provider

    def import_xml(self, xml: Any):
        self._set_provider(self._load_xml(xml))

    def export_xml(self, include_private: bool = False) -> str:
        provider = self._require()
        if include_private and provider.PublicOnly:
            raise SignatureError("Імпортовано лише відкритий ключ: закритого ключа немає.")
        return str(provider.ToXmlString(include_private))

    def public_signer(self) -> "NetSigner":
        return type(self)(None, self.export_xml(False))

    def _check_hash(self, algorithm: str):
        if algorithm not in self.HASHES:
            raise SignatureError(f"{self.NAME} у .NET підтримує геш-алгоритми: {', '.join(self.HASHES)}, а не {algorithm!r}.")

    def sign_hash(self, digest: bytes, algorithm: str = "SHA1") -> bytes:
        self._check_hash(algorithm)
        provider = self._require()
        if provider.PublicOnly:
            raise SignatureError("Для підписування потрібен закритий ключ, а імпортовано лише відкритий.")
        try:
            return bytes(provider.SignHash(bytes(digest), algorithm.lower()))
        except NetException as e:
            raise SignatureError(f"Не вдалося підписати геш: {e.Message.strip()}") from None

    def verify_hash(self, digest: bytes, signature: bytes, algorithm: str = "SHA1") -> bool:
        self._check_hash(algorithm)
        if not isinstance(signature, (bytes, bytearray)):
            raise TypeError("Підпис має бути байтами (bytes).")
        if len(signature) != self.signature_size:
            raise SignatureError(f"Довжина підпису {self.NAME} для цього ключа має бути {self.signature_size} байт, "
                                 f"а отримано {len(signature)}: ймовірно, підпис обрізано або створено іншим ключем.")
        try:
            return bool(self._require().VerifyHash(bytes(digest), algorithm.lower(), bytes(signature)))
        except NetException:
            return False

    def sign(self, message: Any, algorithm: str = "SHA1") -> bytes:
        self._check_hash(algorithm)
        return self.sign_hash(compute_hash(message_bytes(message), algorithm), algorithm)

    def verify(self, message: Any, signature: bytes, algorithm: str = "SHA1") -> bool:
        self._check_hash(algorithm)
        return self.verify_hash(compute_hash(message_bytes(message), algorithm), signature, algorithm)

    def sign_text(self, message: Any, fmt: str = "HEX", algorithm: str = "SHA1") -> str:
        if fmt not in SIGNATURE_FORMATS:
            raise SignatureError(f"Невідомий формат підпису: {fmt!r}. Доступні: {', '.join(SIGNATURE_FORMATS)}.")
        return encode_signature(self.sign(message, algorithm), fmt)

    def verify_text(self, message: Any, signature: str, fmt: str = "HEX", algorithm: str = "SHA1",
                    public_xml: Optional[str] = None) -> bool:
        verifier = type(self)(None, public_xml) if public_xml is not None else self
        return verifier.verify(message, decode_signature(signature, fmt), algorithm)

    def validate_key(self, key: Any) -> bool:
        try:
            self._load_xml(key).Dispose()
            return True
        except (TypeError, SignatureError):
            return False

    def validate_data(self, data: Any) -> bool:
        return isinstance(data, (str, bytes, bytearray)) and len(data) > 0

    def encrypt(self, data: Any, key: Optional[str] = None) -> bytes:
        signer = type(self)(None, key) if key is not None else self
        return signer.sign(data)

    def decrypt(self, data: Tuple[Any, bytes], key: Optional[str] = None) -> bool:
        if not isinstance(data, tuple) or len(data) != 2:
            raise TypeError("Для перевірки передайте пару (повідомлення, підпис).")
        verifier = type(self)(None, key) if key is not None else self
        return verifier.verify(*data)


class NetRSASigner(NetSigner):
    NAME = "RSA"
    PROVIDER = RSACryptoServiceProvider
    XML_TAGS = ("RSAKeyValue", "Modulus", "Exponent")
    HASHES = ("SHA1", "SHA256", "SHA512")
    KEY_SIZES = RSA_SIGN_KEY_SIZES

    @property
    def signature_size(self) -> int:
        return (self.key_size + 7) // 8

    def public_numbers(self) -> Tuple[int, int]:
        params = self._require().ExportParameters(False)
        return int.from_bytes(bytes(params.Modulus), "big"), int.from_bytes(bytes(params.Exponent), "big")


class NetDSASigner(NetSigner):
    NAME = "DSA"
    PROVIDER = DSACryptoServiceProvider
    XML_TAGS = ("DSAKeyValue", "P", "Q", "G", "Y")
    HASHES = ("SHA1",)
    KEY_SIZES = DSA_SIGN_KEY_SIZES

    @property
    def signature_size(self) -> int:
        # Підпис DSA - пара (r, s), кожне число має довжину q (160 біт)
        return 2 * len(bytes(self._require().ExportParameters(False).Q))

    def public_numbers(self) -> Tuple[int, int, int, int]:
        params = self._require().ExportParameters(False)
        return tuple(int.from_bytes(bytes(v), "big") for v in (params.P, params.Q, params.G, params.Y))
