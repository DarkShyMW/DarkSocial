"""
models.py — доменная модель FurryNet: аккаунты, возрастная верификация,
настройки видимости, доверие и обмен ключами.

Правила защиты от детей:
  * Аккаунт с VERIFIED=False не может публиковать контент с рейтингом
    NSFW (adult) и не видит такой контент у других.
  * Рейтинги контента: "safe" | "nsfw".
  * Настройки видимости профиля: "public" | "friends" | "mutual_trust" | "private".
    - public       — виден базовый профиль всем верифицированным;
    - friends      — только тем, кого пользователь одобрил как друзей;
    - mutual_trust — только участникам с взаимным доверием И обменом ключами;
    - private      — никому (только владельцу).
  * Гостевые (unverified / minor) аккаунты в принципе не получают доступ
    к профилям с рейтингом nsfw и к аватарам за пределами "public".
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum

MIN_ADULT_AGE = 18


class Visibility(str, Enum):
    PUBLIC = "public"
    FRIENDS = "friends"
    MUTUAL_TRUST = "mutual_trust"
    PRIVATE = "private"


class ContentRating(str, Enum):
    SAFE = "safe"
    NSFW = "nsfw"


@dataclass
class Account:
    uid: int
    username: str
    password_hash: str                 # argon2/bcrypt-совместимый хеш (см. auth.py)
    birth_date: str                    # ISO yyyy-mm-dd — введён при регистрации
    age: int                           # вычисленный на момент проверки документов
    verified: bool = False             # пройдена строгая проверка возраста
    verification_method: str | None = None   # "id_document" | "face_age_estimation"
    adult_ok: bool = False             # подтверждено совершеннолетие >=18
    public_key_pem: str = ""           # публичный ключ участника
    encrypted_private_pem: str = ""    # приватный ключ, зашифрованный паролем
    visibility: str = Visibility.MUTUAL_TRUST.value
    created_at: float = field(default_factory=time.time)

    def is_adult(self) -> bool:
        return self.verified and self.adult_ok and self.age >= MIN_ADULT_AGE

    def to_public_row(self) -> dict:
        """Минимальная запись для индексной базы (без секретов)."""
        return {
            "uid": self.uid,
            "username": self.username,
            "verified": int(self.verified),
            "adult_ok": int(self.adult_ok),
            "visibility": self.visibility,
            "public_key_pem": self.public_key_pem,
        }


@dataclass
class TrustLink:
    """Одностороннее доверие: truster доверяет trusted."""
    truster_uid: int
    trusted_uid: int
    created_at: float = field(default_factory=time.time)


@dataclass
class Post:
    pid: int
    author_uid: int
    rating: str                        # ContentRating
    enc_key: str                       # ключ файла в EncryptedFileStore
    created_at: float = field(default_factory=time.time)


def compute_age(birth_iso: str, now: float | None = None) -> int:
    from datetime import date
    y, m, d = map(int, birth_iso.split("-"))
    today = date.fromtimestamp(now or time.time())
    years = today.year - y
    if (today.month, today.day) < (m, d):
        years -= 1
    return years


def can_view_profile(viewer: Account | None, target: Account,
                     is_mutual_trusted: bool, keys_exchanged: bool,
                     is_friend: bool) -> tuple[bool, str]:
    """Центральная функция контроля доступа к профилю/аватару.

    Возвращает (разрешено, причина).
    """
    if viewer is None:
        return False, "anonymous"
    if viewer.uid == target.uid:
        return True, "owner"

    vis = Visibility(target.visibility)

    # Защита от несовершеннолетних: неверифицированные аккаунты
    # не видят ничего, кроме полностью публичных профилей safe-контента.
    if not viewer.is_adult():
        if vis == Visibility.PUBLIC:
            return True, "public_to_all"
        return False, "age_verification_required"

    match vis:
        case Visibility.PRIVATE:
            return False, "private"
        case Visibility.PUBLIC:
            return True, "public"
        case Visibility.FRIENDS:
            return (True, "friend") if is_friend else (False, "not_friend")
        case Visibility.MUTUAL_TRUST:
            if is_mutual_trusted and keys_exchanged:
                return True, "mutual_trust_keys"
            if is_mutual_trusted and not keys_exchanged:
                return False, "keys_not_exchanged"
            return False, "no_mutual_trust"
    return False, "unknown"
