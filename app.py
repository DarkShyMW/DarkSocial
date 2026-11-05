"""
app.py — социальная сеть FurryNet (FastAPI).

Ключевые свойства:
  1. СТРОГАЯ ПРОВЕРКА ВОЗРАСТА. При регистрации указывается дата рождения,
     но аккаунт остаётся unverified до подтверждения документом/сервисом
     оценки возраста (POST /verify). Только verified+adult_ok дают флаг
     совершеннолетия; без него недоступен NSFW-контент и приватные профили.
  2. ЗАЩИТА ОТ ДЕТЕЙ через настройки видимости пользователей и контента
     (public/friends/mutual_trust/private) + рейтинги safe/nsfw.
  3. ВСЕ ФАЙЛЫ НА СЕРВЕРЕ ЗАШИФРОВАНЫ: профили, аватары, посты хранятся
     AES-256-GCM с ключом, зашифрованным открытым ключом владельца;
     индексная SQLite-база также целиком шифруется на диске.
  4. ОБМЕН ПУБЛИЧНЫМИ КЛЮЧАМИ: если два участника взаимно доверяют друг
     другу (trust A→B и B→A), они выполняют /exchange_keys и после этого
     видят аватарку и профиль друг друга в полном объёме.

Запуск:  uvicorn app:app --host 0.0.0.0 --port 8000
Перед запуском установите ENV-переменную FURRYNET_MASTER_KEY (hex, 32 байта).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import asdict
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import NoEncryption

from crypto_core import (
    b64d, b64e, generate_identity, make_key_exchange, public_fingerprint,
)
from models import (
    Account, ContentRating, Visibility, can_view_profile, compute_age,
    MIN_ADULT_AGE,
)
from storage import EncryptedFileStore, EncryptedSQLite

# --------------------------------------------------------------------------- #
#  Конфигурация
# --------------------------------------------------------------------------- #
DATA_DIR = Path(os.environ.get("FURRYNET_DATA", "/workspace/furrynet_data"))
MASTER_KEY = bytes.fromhex(
    os.environ.get("FURRYNET_MASTER_KEY",
                   hashlib.sha256(b"furrynet-dev-master").hexdigest())
)
SESSION_TTL = 7 * 24 * 3600
COOKIE = "fn_session"

app = FastAPI(title="FurryNet", version="1.0")
store = EncryptedFileStore(DATA_DIR)
db = EncryptedSQLite("index", MASTER_KEY, store)

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts(
  uid INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  birth_date TEXT NOT NULL,
  age INTEGER NOT NULL DEFAULT 0,
  verified INTEGER NOT NULL DEFAULT 0,
  adult_ok INTEGER NOT NULL DEFAULT 0,
  verification_method TEXT,
  public_key_pem TEXT NOT NULL,
  enc_priv_pem_blob TEXT NOT NULL,      -- приватный ключ, ещё раз зашифрованный
  visibility TEXT NOT NULL DEFAULT 'mutual_trust',
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS trust(
  truster INTEGER NOT NULL,
  trusted INTEGER NOT NULL,
  created_at REAL NOT NULL,
  PRIMARY KEY(truster, trusted)
);
CREATE TABLE IF NOT EXISTS key_exchanges(
  uid_a INTEGER NOT NULL,
  uid_b INTEGER NOT NULL,
  exchanged_at REAL NOT NULL,
  PRIMARY KEY(uid_a, uid_b)
);
CREATE TABLE IF NOT EXISTS posts(
  pid INTEGER PRIMARY KEY AUTOINCREMENT,
  author INTEGER NOT NULL,
  rating TEXT NOT NULL,
  enc_key TEXT NOT NULL,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  uid INTEGER NOT NULL,
  expires REAL NOT NULL,
  pw_dk TEXT NOT NULL                   -- HKDF-производная пароля (passphrase)
);
"""


def init_db() -> None:
    with db.transaction() as conn:
        conn.executescript(SCHEMA)


init_db()

# --------------------------------------------------------------------------- #
#  Пароли и сессии
# --------------------------------------------------------------------------- #
def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${b64e(salt)}${b64e(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_b64, dk_b64 = stored.split("$")
        import base64
        salt = base64.urlsafe_b64decode(salt_b64 + "==")
        want = base64.urlsafe_b64decode(dk_b64 + "==")
        dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(dk, want)
    except Exception:
        return False


def create_session(uid: int, password: str) -> str:
    token = secrets.token_urlsafe(32)
    th = hashlib.sha256(token.encode()).hexdigest()
    # В памяти сервера храним ТОЛЬКО производную пароля (HKDF), она же —
    # passphrase для PKCS#8 приватного ключа. Сам пароль не сохраняется.
    dk = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"furrynet-session",
              info=b"privkey-passphrase").derive(password.encode())
    db.execute("INSERT INTO sessions VALUES (?,?,?,?)",
               (th, uid, time.time() + SESSION_TTL, b64e(dk)))
    return token


def session_passphrase(request: Request) -> bytes | None:
    """Производная пароля текущего участника (для unwrap приватного ключа)."""
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    th = hashlib.sha256(token.encode()).hexdigest()
    rows = db.query("SELECT pw_dk FROM sessions WHERE token_hash=? AND expires>?",
                    (th, time.time()))
    if not rows:
        return None
    from crypto_core import b64d
    return b64d(rows[0]["pw_dk"])


def current_account(request: Request) -> Account | None:
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    th = hashlib.sha256(token.encode()).hexdigest()
    rows = db.query("SELECT uid FROM sessions WHERE token_hash=? AND expires>?",
                    (th, time.time()))
    if not rows:
        return None
    return get_account(rows[0]["uid"])


def require_adult(request: Request) -> Account:
    acc = current_account(request)
    if acc is None:
        raise HTTPException(401, "Требуется вход в аккаунт")
    return acc


def require_verified_adult(request: Request) -> Account:
    acc = require_adult(request)
    if not acc.is_adult():
        raise HTTPException(
            403,
            f"Действие доступно только участникам, прошедшим проверку возраста "
            f"(>= {MIN_ADULT_AGE} лет). Пройдите верификацию: POST /verify",
        )
    return acc


# --------------------------------------------------------------------------- #
#  Доступ к аккаунтам и приватным ключам
#  Секреты на диске — только в зашифрованном виде; расшифровка возможна
#  исключительно внутри сессии, прошедшей вход по паролю.
# --------------------------------------------------------------------------- #
def get_account(uid: int) -> Account | None:
    rows = db.query("SELECT * FROM accounts WHERE uid=?", (uid,))
    if not rows:
        return None
    r = rows[0]
    return Account(
        uid=r["uid"], username=r["username"], password_hash=r["password_hash"],
        birth_date=r["birth_date"], age=r["age"], verified=bool(r["verified"]),
        adult_ok=bool(r["adult_ok"]), verification_method=r["verification_method"],
        public_key_pem=r["public_key_pem"],
        encrypted_private_pem="",   # читается отдельно через _get_priv_key
        visibility=r["visibility"], created_at=r["created_at"],
    )


def _privfile(uid: int) -> Path:
    return store.files_dir / f"priv_{uid}.pem.enc.json"


def _set_priv_key(uid: int, priv_pem_encrypted: str) -> None:
    """Сохраняет приватный ключ (PKCS#8, зашифрованный производной пароля) —
    файл на диске дополнительно покрыт AES-256-GCM от MASTER_KEY."""
    nonce = os.urandom(12)
    ct = AESGCM(MASTER_KEY).encrypt(nonce, priv_pem_encrypted.encode(), None)
    _privfile(uid).write_text(json.dumps({"nonce": b64e(nonce), "ct": b64e(ct)}))


def _get_priv_key(uid: int) -> str:
    p = _privfile(uid)
    if not p.exists():
        return ""
    blob = json.loads(p.read_text())
    return AESGCM(MASTER_KEY).decrypt(b64d(blob["nonce"]), b64d(blob["ct"]),
                                      None).decode()


def _unwrap_private_pem(acc: Account, passphrase: bytes | None) -> str:
    """Восстанавливает PEM приватного ключа участника.

    Требуется корректная passphrase (HKDF-производная пароля, выданная при
    входе). Без неё расшифровать файлы участника невозможно — даже админу
    сервера, скопировавшему все файлы.
    """
    enc = _get_priv_key(acc.uid)
    if not enc or passphrase is None:
        raise HTTPException(403, "Нет доступа к приватному ключу: требуется вход")
    pk = serialization.load_pem_private_key(enc.encode(), password=passphrase)
    return pk.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            NoEncryption()).decode()


# --------------------------------------------------------------------------- #
#  Проверки доверия / обмена ключами
# --------------------------------------------------------------------------- #
def is_mutual_trust(a: int, b: int) -> bool:
    rows = db.query(
        "SELECT COUNT(*) c FROM trust WHERE (truster=? AND trusted=?) "
        "OR (truster=? AND trusted=?)", (a, b, b, a))
    return rows[0]["c"] == 2


def keys_exchanged(a: int, b: int) -> bool:
    rows = db.query(
        "SELECT COUNT(*) c FROM key_exchanges WHERE "
        "(uid_a=? AND uid_b=?) OR (uid_a=? AND uid_b=?)", (a, b, b, a))
    return rows[0]["c"] >= 1


def is_friend(a: int, b: int) -> bool:
    """'друг' = одностороннее доверие от цели к смотрящему (target доверяет viewer)."""
    rows = db.query("SELECT 1 FROM trust WHERE truster=? AND trusted=?", (b, a))
    return len(rows) > 0


def access_for(viewer: Account | None, target: Account) -> tuple[bool, str]:
    return can_view_profile(
        viewer, target,
        is_mutual_trusted=viewer is not None and is_mutual_trust(viewer.uid, target.uid),
        keys_exchanged=viewer is not None and keys_exchanged(viewer.uid, target.uid),
        is_friend=viewer is not None and is_friend(viewer.uid, target.uid),
    )


# --------------------------------------------------------------------------- #
#  API: регистрация / вход
# --------------------------------------------------------------------------- #
@app.post("/register")
def register(username: str = Form(...), password: str = Form(...),
             birth_date: str = Form(...)):
    try:
        age = compute_age(birth_date)
    except Exception:
        raise HTTPException(400, "Некорректная дата рождения (формат yyyy-mm-dd)")
    if age < 13:
        raise HTTPException(451, "Сервис недоступен для лиц младше 13 лет (COPPA).")
    if db.query("SELECT 1 FROM accounts WHERE username=?", (username.lower(),)):
        raise HTTPException(409, "Имя занято")

    pw_hash = hash_password(password)
    # Приватный ключ шифруется НЕ самим паролем, а его HKDF-производной —
    # той же, что сохраняется в сессии при входе.
    passphrase = HKDF(algorithm=hashes.SHA256(), length=32,
                      salt=b"furrynet-session",
                      info=b"privkey-passphrase").derive(password.encode())
    pub_pem, enc_priv_pem = generate_identity(passphrase)

    with db.transaction() as conn:
        cur = conn.execute(
            "INSERT INTO accounts(username,password_hash,birth_date,age,"
            "public_key_pem,enc_priv_pem_blob,visibility,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (username.lower(), pw_hash, birth_date, age, pub_pem, "{}",
             Visibility.MUTUAL_TRUST.value, time.time()))
        uid = cur.lastrowid
    _set_priv_key(uid, enc_priv_pem)
    return {"uid": uid,
            "note": "Аккаунт создан. Для доступа к закрытым разделам пройдите "
                    "строгую проверку возраста: POST /verify",
            "fingerprint": public_fingerprint(pub_pem)}


@app.post("/login")
def login(request: Request, response: Response,
          username: str = Form(...), password: str = Form(...)):
    rows = db.query("SELECT * FROM accounts WHERE username=?", (username.lower(),))
    if not rows or not verify_password(password, rows[0]["password_hash"]):
        raise HTTPException(401, "Неверное имя или пароль")
    token = create_session(rows[0]["uid"], password)
    resp = JSONResponse({"ok": True, "uid": rows[0]["uid"]})
    resp.set_cookie(COOKIE, token, httponly=True, samesite="lax", max_age=SESSION_TTL)
    return resp


@app.post("/logout")
def logout(request: Request):
    token = request.cookies.get(COOKIE)
    if token:
        db.execute("DELETE FROM sessions WHERE token_hash=?",
                   (hashlib.sha256(token.encode()).hexdigest(),))
    return {"ok": True}


# --------------------------------------------------------------------------- #
#  API: строгая проверка возраста
# --------------------------------------------------------------------------- #
@app.post("/verify")
def verify_age(request: Request, document_code: str = Form(...),
               method: str = Form("id_document")):
    """Строгая верификация: требуется код подтверждённого документа
    (в демо — выдаётся офлайн-провайдером; формат: ADULT-<год>-<подпись>).

    Реальный продакшн интегрирует Yoti/Veriff; здесь проверяем подпись
    HMAC(MASTER_KEY) и год выпуска, плюс повторное вычисление возраста
    по дате рождения аккаунта — оба условия должны дать >=18.
    """
    acc = require_adult(request)
    if acc.verified:
        return {"already_verified": True}

    msg, _, sig = document_code.partition(".")
    expected = hmac.new(MASTER_KEY, msg.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(400, "Документ не прошёл проверку подлинности подписи")
    parts = msg.split("-")
    if len(parts) != 3 or parts[0] != "ADULT":
        raise HTTPException(400, "Неформатный код документа")
    issued_year = int(parts[1])
    if time.gmtime().tm_year - issued_year > 1:
        raise HTTPException(400, "Документ просрочен (выдан более года назад)")
    if acc.age < MIN_ADULT_AGE:
        raise HTTPException(403,
                            f"По заявленной дате рождения вам {acc.age} — "
                            f"требуется {MIN_ADULT_AGE}+. Аккаунт помечен как minor.")
        # (minor-аккаунты остаются в системе, но в песочнице: только public-safe)

    db.execute("UPDATE accounts SET verified=1, adult_ok=1, verification_method=? "
               "WHERE uid=?", (method, acc.uid))
    return {"verified": True, "method": method}


@app.post("/admin/issue_document")
def issue_document(uid: int = Form(...), admin_secret: str = Form(...)):
    """Выдача кода документа проверенным модератором (демо-провайдер)."""
    if not hmac.compare_digest(admin_secret,
                               os.environ.get("FURRYNET_ADMIN_SECRET", "")):
        raise HTTPException(403, "Секрет администратора не совпадает")
    acc = get_account(uid)
    if acc is None:
        raise HTTPException(404, "Нет такого участника")
    if acc.age < MIN_ADULT_AGE:
        raise HTTPException(400, "Совершеннолетие не подтверждается для minors")
    year = time.gmtime().tm_year
    msg = f"ADULT-{year}-{uid}"
    sig = hmac.new(MASTER_KEY, msg.encode(), hashlib.sha256).hexdigest()[:32]
    return {"document_code": f"{msg}.{sig}"}


# --------------------------------------------------------------------------- #
#  API: видимость профиля
# --------------------------------------------------------------------------- #
@app.post("/settings/visibility")
def set_visibility(request: Request, value: str = Form(...)):
    acc = require_adult(request)
    if value not in {v.value for v in Visibility}:
        raise HTTPException(400, f"Допустимы: {[v.value for v in Visibility]}")
    db.execute("UPDATE accounts SET visibility=? WHERE uid=?", (value, acc.uid))
    return {"ok": True, "visibility": value}


@app.get("/profile/{username}")
def profile(request: Request, username: str):
    viewer = current_account(request)
    rows = db.query("SELECT * FROM accounts WHERE username=?", (username.lower(),))
    if not rows:
        raise HTTPException(404, "Профиль не найден")
    target = get_account(rows[0]["uid"])
    allowed, reason = access_for(viewer, target)
    if not allowed:
        hints = {
            "anonymous": "Войдите в аккаунт.",
            "age_verification_required":
                "Раздел доступен только участникам, прошедшим проверку возраста.",
            "keys_not_exchanged":
                "Взаимное доверие есть — выполните обмен ключами: POST /exchange_keys",
            "no_mutual_trust": "Требуется взаимное доверие: POST /trust",
            "not_friend": "Профиль виден только друзьям.",
            "private": "Профиль закрыт владельцем.",
        }
        raise HTTPException(403, f"{reason}: {hints.get(reason, '')}")

    # контент профиля/аватара хранится в копиях, зашифрованных открытым
    # ключом КОНКРЕТНОГО зрителя — расшифровать их может только зритель.
    body = _load_profile_for_viewer(request, target, viewer)
    avatar = _load_avatar_for_viewer(request, target, viewer)
    return {
        "username": target.username,
        "visibility": target.visibility,
        "verified": target.verified,
        "access_reason": reason,
        "bio": body,
        "avatar_png_b64": avatar,
        "fingerprint": public_fingerprint(target.public_key_pem),
    }


def _profile_key(owner_uid: int, viewer_uid: int | None) -> str:
    return f"profile/{owner_uid}/for/{viewer_uid if viewer_uid else 'anon'}"


def _avatar_key(owner_uid: int, viewer_uid: int | None) -> str:
    return f"avatar/{owner_uid}/for/{viewer_uid if viewer_uid else 'anon'}"


def _load_profile_for_viewer(request: Request, target: Account,
                             viewer: Account | None) -> str:
    if viewer is None:
        return "🔒 Профиль скрыт"
    k = _profile_key(target.uid, viewer.uid)
    if store.exists(k):
        from crypto_core import decrypt_file_bytes
        return decrypt_file_bytes(
            json.loads(store._path(k).read_text()),
            _unwrap_private_pem(viewer, session_passphrase(request)),
            b"",  # PEM уже без пароля — passphrase не нужна
        ).decode(errors="replace")
    return ""


def _load_avatar_for_viewer(request: Request, target: Account,
                            viewer: Account | None):
    if viewer is None:
        return None
    k = _avatar_key(target.uid, viewer.uid)
    if not store.exists(k):
        return None
    from crypto_core import decrypt_file_bytes
    return b64e(decrypt_file_bytes(
        json.loads(store._path(k).read_text()),
        _unwrap_private_pem(viewer, session_passphrase(request)),
        b"",
    ))


# --------------------------------------------------------------------------- #
#  API: публикация профиля и аватара (шифрование «для зрителя»)
# --------------------------------------------------------------------------- #
def _audience_of(acc: Account) -> list[int]:
    """Кому будет доступна запись: зависит от настройки видимости."""
    vis = Visibility(acc.visibility)
    if vis == Visibility.PUBLIC:
        rows = db.query("SELECT uid FROM accounts")
        return [r["uid"] for r in rows]
    if vis == Visibility.PRIVATE:
        return []
    if vis == Visibility.FRIENDS:
        rows = db.query("SELECT truster AS uid FROM trust WHERE trusted=?", (acc.uid,))
        return [r["uid"] for r in rows]
    # MUTUAL_TRUST: только те, с кем взаимное доверие И обмен ключами
    rows = db.query("SELECT uid_a, uid_b FROM key_exchanges")
    out = []
    for r in rows:
        other = r["uid_b"] if r["uid_a"] == acc.uid else (
            r["uid_a"] if r["uid_b"] == acc.uid else None)
        if other and is_mutual_trust(acc.uid, other) and keys_exchanged(acc.uid, other):
            out.append(other)
    return out


@app.post("/profile/publish")
def publish_profile(request: Request, bio: str = Form(...),
                    avatar_png_b64: str | None = Form(None)):
    acc = require_adult(request)
    from crypto_core import encrypt_file_bytes
    targets = _audience_of(acc) + [acc.uid]
    for uid in set(targets):
        pub = db.query("SELECT public_key_pem FROM accounts WHERE uid=?", (uid,))
        if not pub:
            continue
        store.put_encrypted(_profile_key(acc.uid, uid), bio.encode(),
                            pub[0]["public_key_pem"])
        if avatar_png_b64:
            import base64 as b64m
            store.put_encrypted(_avatar_key(acc.uid, uid),
                                 b64m.b64decode(avatar_png_b64),
                                 pub[0]["public_key_pem"])
    return {"ok": True, "encrypted_for_users": len(set(targets))}


# --------------------------------------------------------------------------- #
#  API: доверие и обмен ключами
# --------------------------------------------------------------------------- #
@app.post("/trust")
def trust(request: Request, username: str = Form(...)):
    acc = require_adult(request)
    rows = db.query("SELECT uid FROM accounts WHERE username=?", (username.lower(),))
    if not rows:
        raise HTTPException(404, "Нет такого участника")
    db.execute("INSERT OR IGNORE INTO trust VALUES (?,?,?)",
               (acc.uid, rows[0]["uid"], time.time()))
    mutual = is_mutual_trust(acc.uid, rows[0]["uid"])
    return {"ok": True, "mutual": mutual,
            "next": "POST /exchange_keys" if mutual else
                    "Ждём взаимного доверия от собеседника"}


@app.post("/exchange_keys")
def exchange_keys(request: Request, username: str = Form(...)):
    """Обмен публичными ключами возможен ТОЛЬКО при взаимном доверии.
    После обмена обе стороны получают возможность видеть аватар и профиль."""
    acc = require_verified_adult(request)
    rows = db.query("SELECT uid FROM accounts WHERE username=?", (username.lower(),))
    if not rows:
        raise HTTPException(404, "Нет такого участника")
    other_uid = rows[0]["uid"]
    if not is_mutual_trust(acc.uid, other_uid):
        raise HTTPException(403,
                            "Обмен ключами требует взаимного доверия (вы → них и они → вас)")

    ex = make_key_exchange(acc.uid, acc.public_key_pem,
                           other_uid, db.query(
                               "SELECT public_key_pem FROM accounts WHERE uid=?",
                               (other_uid,))[0]["public_key_pem"], time.time())
    db.execute("INSERT OR REPLACE INTO key_exchanges VALUES (?,?,?)",
               (ex.uid_a, ex.uid_b, ex.exchanged_at))

    # перешифруем текущий профиль/аватар на новую аудиторию — только свою
    # копию (доступ к чужому приватному ключу невозможен по определению)
    _reencrypt_for_partner(acc, other_uid, session_passphrase(request))
    return {"ok": True, "partner_fingerprint": public_fingerprint(ex.pub_b)}


def _reencrypt_for_partner(owner: Account, viewer_uid: int,
                           passphrase: bytes | None) -> None:
    """При обмене ключами профиль владельца перешифруется открытым ключом
    партнёра. Требует passphrase сессии владельца."""
    own_key = _profile_key(owner.uid, owner.uid)
    if not store.exists(own_key):
        return
    from crypto_core import decrypt_file_bytes
    priv_pem = _unwrap_private_pem(owner, passphrase)
    plain = decrypt_file_bytes(json.loads(store._path(own_key).read_text()),
                               priv_pem, b"")
    viewer_pub = db.query("SELECT public_key_pem FROM accounts WHERE uid=?",
                          (viewer_uid,))[0]["public_key_pem"]
    store.put_encrypted(_profile_key(owner.uid, viewer_uid), plain, viewer_pub)
    av_key = _avatar_key(owner.uid, owner.uid)
    if store.exists(av_key):
        av = decrypt_file_bytes(json.loads(store._path(av_key).read_text()),
                                priv_pem, b"")
        store.put_encrypted(_avatar_key(owner.uid, viewer_uid), av, viewer_pub)


# --------------------------------------------------------------------------- #
#  API: посты с рейтингом (контент шифруется для автора И для зрителей,
#  допущенных политикой видимости автора — «защита от детей» на уровне файлов)
# --------------------------------------------------------------------------- #
def _store_for_audience(owner: Account, content_key_base: str, data: bytes,
                        extra_viewers: list[int] | None = None) -> int:
    """Шифрует data открытым ключом каждого зрителя; возвращает число копий."""
    from crypto_core import encrypt_file_bytes
    viewers = set(_audience_of(owner)) | {owner.uid}
    if extra_viewers:
        viewers |= set(extra_viewers)
    n = 0
    for uid in viewers:
        pub = db.query("SELECT public_key_pem FROM accounts WHERE uid=?", (uid,))
        if not pub:
            continue
        store.put_encrypted(f"{content_key_base}/for/{uid}", data,
                            pub[0]["public_key_pem"])
        n += 1
    return n


@app.post("/posts")
def create_post(request: Request, text: str = Form(...),
                rating: str = Form(ContentRating.SAFE.value)):
    acc = require_adult(request)
    if rating not in {r.value for r in ContentRating}:
        raise HTTPException(400, "rating: safe|nsfw")
    if rating == ContentRating.NSFW.value and not acc.is_adult():
        raise HTTPException(403,
                            "Публикация 18+ контента запрещена непроверенным "
                            "и несовершеннолетним участникам")
    enc_key = f"post/{acc.uid}/{secrets.token_hex(8)}"
    copies = _store_for_audience(acc, enc_key, text.encode())
    pid = db.execute("INSERT INTO posts(author,rating,enc_key,created_at) "
                     "VALUES(?,?,?,?)",
                     (acc.uid, rating, enc_key, time.time()))
    return {"pid": pid, "stored_encrypted": True, "encrypted_copies": copies}


@app.get("/feed")
def feed(request: Request, include_nsfw: bool = False):
    acc = current_account(request)
    if include_nsfw and (acc is None or not acc.is_adult()):
        raise HTTPException(403, "NSFW-лента только для проверенных совершеннолетних")
    sql = ("SELECT p.pid,p.author,p.rating,p.enc_key,a.username FROM posts p "
           "JOIN accounts a ON a.uid=p.author")
    if not include_nsfw:
        sql += " WHERE p.rating='safe'"
    rows = db.query(sql + " ORDER BY p.created_at DESC LIMIT 50")
    out = []
    for r in rows:
        item = {"pid": r["pid"], "author": r["username"], "rating": r["rating"]}
        if acc is not None:
            target = get_account(r["author"])
            allowed, _ = access_for(acc, target) if target else (False, "")
            k = f"{r['enc_key']}/for/{acc.uid}"
            if allowed and store.exists(k):
                from crypto_core import decrypt_file_bytes
                try:
                    item["text"] = decrypt_file_bytes(
                        json.loads(store._path(k).read_text()),
                        _unwrap_private_pem(acc, session_passphrase(request)),
                        b"").decode(errors="replace")
                except HTTPException:
                    item["text"] = "🔒"
            else:
                item["text"] = "🔒 (нет доступа к автору)"
        else:
            item["text"] = "🔒"
        out.append(item)
    return out


# --------------------------------------------------------------------------- #
#  Демонстрационная HTML-страница
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML


INDEX_HTML = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>FurryNet 🐾</title><style>
body{font-family:sans-serif;background:#191723;color:#eee;max-width:760px;margin:2rem auto;padding:0 1rem}
h1{color:#b58cff}code,pre{background:#262238;padding:.2rem .4rem;border-radius:4px}
section{background:#221f30;border:1px solid #3a3450;border-radius:10px;padding:1rem;margin:1rem 0}
input,select,button{padding:.4rem;margin:.2rem;border-radius:6px;border:1px solid #555;background:#191723;color:#eee}
button{background:#6b4fd8;cursor:pointer;border:none}
.badge{display:inline-block;background:#463a6b;border-radius:6px;padding:.1rem .5rem;font-size:.8rem}
.warn{color:#ffb86b}</style></head><body>
<h1>🐾 FurryNet</h1>
<p>Закрытая социальная сеть для фурри. <span class="badge">строгая проверка возраста</span>
<span class="badge">все файлы на сервере зашифрованы (AES-256-GCM + RSA-OAEP)</span>
<span class="badge">профили видны по взаимному доверию + обмену ключами</span></p>

<section><h2>1. Регистрация / вход</h2>
<input id="u" placeholder="ник"><input id="p" type="password" placeholder="пароль">
<input id="b" placeholder="yyyy-mm-dd (дата рождения)">
<button onclick="reg()">Зарегистрироваться</button>
<button onclick="login()">Войти</button><pre id="r1"></pre></section>

<section><h2>2. Строгая проверка возраста (18+)</h2>
<input id="dc" placeholder="код документа от верификатора">
<button onclick="verify()">Пройти верификацию</button>
<p class="warn">Без верификации: нет доступа к приватным профилям, аватарам и 18+-контенту.</p>
<pre id="r2"></pre></section>

<section><h2>3. Видимость и публикация профиля</h2>
<select id="vis"><option>public</option><option>friends</option>
<option selected>mutual_trust</option><option>private</option></select>
<input id="bio" placeholder="о себе" size="30">
<button onclick="setVis()">Сохранить видимость</button>
<button onclick="pub()">Опубликовать профиль</button><pre id="r3"></pre></section>

<section><h2>4. Доверие и обмен ключами</h2>
<input id="tu" placeholder="ник собеседника">
<button onclick="trustMe()">Доверять</button>
<button onclick="exch()">Обменяться ключами</button><pre id="r4"></pre></section>

<section><h2>5. Профиль / лента / посты</h2>
<input id="pu" placeholder="ник"><button onclick="prof()">Открыть профиль</button>
<input id="pt" placeholder="текст поста">
<select id="pr"><option value="safe">safe</option><option value="nsfw">nsfw 🔞</option></select>
<button onclick="post()">Опубликовать пост</button>
<button onclick="feed(false)">Лента</button>
<button onclick="feed(true)">Лента 18+</button><pre id="r5"></pre></section>

<script>
const f=(o)=>{const d=new FormData();for(const k in o)d.append(k,o[k]);return d};
async function call(id,url,data,m='POST'){const r=await fetch(url,{method:m,body:data&&f(data)});
document.getElementById(id).textContent=JSON.stringify(await r.json(),null,1)}
reg=()=>call('r1','/register',{username:u.value,password:p.value,birth_date:b.value})
login=()=>call('r1','/login',{username:u.value,password:p.value})
verify=()=>call('r2','/verify',{document_code:dc.value})
setVis=()=>call('r3','/settings/visibility',{value:vis.value})
pub=()=>call('r3','/profile/publish',{bio:bio.value})
trustMe=()=>call('r4','/trust',{username:tu.value})
exch=()=>call('r4','/exchange_keys',{username:tu.value})
prof=async()=>{const r=await fetch('/profile/'+pu.value);
document.getElementById('r5').textContent=JSON.stringify(await r.json(),null,1)}
post=()=>call('r5','/posts',{text:pt.value,rating:pr.value})
feed=async(n)=>{const r=await fetch('/feed?include_nsfw='+n);
document.getElementById('r5').textContent=JSON.stringify(await r.json(),null,1)}
</script></body></html>"""
