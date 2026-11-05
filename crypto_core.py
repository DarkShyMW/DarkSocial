"""
crypto_core.py — криптографическое ядро социальной сети FurryNet.

Обеспечивает:
  * Генерацию пары RSA-ключей (2048 бит) для каждого участника.
  * Шифрование всех файлов на сервере симметричным AES-256-GCM,
    ключ которого сам зашифрован открытым ключом владельца (гибридная схема).
  * Обмен публичными ключами между участниками, которым они доверяют
    друг другу взаимно (trust mutual).
  * Расшифровку профиля/аватара только у взаимно доверяющих участников.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# --------------------------------------------------------------------------- #
#  Утилиты base64
# --------------------------------------------------------------------------- #
def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))


# --------------------------------------------------------------------------- #
#  Гибридное шифрование файла: AES-256-GCM + RSA-OAEP(SHA-256)
# --------------------------------------------------------------------------- #
def encrypt_file_bytes(plaintext: bytes, recipient_public_key_pem: str) -> dict:
    """Шифрует произвольные байты для владельца открытого ключа.

    Возвращает структуру, которую можно сохранить как JSON-файл на диске:
       { "ek": <зашифрованный ключ AES>, "nonce": ..., "ct": ..., "tag": ... }
    """
    pub = serialization.load_pem_public_key(recipient_public_key_pem.encode())
    aes_key = os.urandom(32)                      # одноразовый ключ файла (FEK)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    encrypted_key = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None),
    )
    return {
        "alg": "RSA-OAEP-256+AES-256-GCM",
        "ek": b64e(encrypted_key),
        "nonce": b64e(nonce),
        "ct": b64e(ct_with_tag),
    }


def decrypt_file_bytes(blob: dict, private_key_pem: str, passphrase: bytes) -> bytes:
    """Расшифровывает blob, полученный из encrypt_file_bytes."""
    priv = serialization.load_pem_private_key(
        private_key_pem.encode(), password=passphrase
    )
    aes_key = priv.decrypt(
        b64d(blob["ek"]),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None),
    )
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(b64d(blob["nonce"]), b64d(blob["ct"]), None)


# --------------------------------------------------------------------------- #
#  Хранение приватного ключа: приватный ключ шифруется паролем аккаунта
# --------------------------------------------------------------------------- #
def generate_identity(passphrase: bytes) -> tuple[str, str]:
    """Возвращает (public_pem, encrypted_private_pem_base64)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    ).decode()

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return public_pem, private_pem


def unwrap_private_key(encrypted_private_pem: str, passphrase: bytes) -> str:
    """Проверяет пароль, возвращая PEM приватного ключа в открытом виде
    (только в памяти процесса, никогда не сохраняется на диск)."""
    serialization.load_pem_private_key(
        encrypted_private_pem.encode(), password=passphrase
    )
    return encrypted_private_pem  # уже зашифрован паролем — храним как есть


def public_fingerprint(public_pem: str) -> str:
    """Короткий отпечаток публичного ключа (для отображения пользователю)."""
    pub = serialization.load_pem_public_key(public_pem.encode())
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return b64e(digest.finalize())[:16]


# --------------------------------------------------------------------------- #
#  Обмен ключами по взаимному доверию
# --------------------------------------------------------------------------- #
@dataclass
class KeyExchange:
    """Запись обмена публичными ключами между двумя uid."""
    uid_a: int
    uid_b: int
    pub_a: str          # публичный ключ A, сохранённый у B
    pub_b: str          # публичный ключ B, сохранённый у A
    exchanged_at: float

    def to_dict(self) -> dict:
        return {
            "uid_a": self.uid_a,
            "uid_b": self.uid_b,
            "pub_a": self.pub_a,
            "pub_b": self.pub_b,
            "exchanged_at": self.exchanged_at,
        }

    @staticmethod
    def from_dict(d: dict) -> "KeyExchange":
        return KeyExchange(
            uid_a=d["uid_a"], uid_b=d["uid_b"],
            pub_a=d["pub_a"], pub_b=d["pub_b"],
            exchanged_at=d["exchanged_at"],
        )


def make_key_exchange(uid_a: int, pub_a: str, uid_b: int, pub_b: str,
                      timestamp: float) -> KeyExchange:
    return KeyExchange(uid_a, uid_b, pub_a, pub_b, timestamp)
