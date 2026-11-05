"""
storage.py — зашифрованное файловое хранилище FurryNet.

Требование: «Все файлы должны быть на сервере зашифрованы».

Реализация:
  * Каждый логический объект (профиль, аватар, пост) хранится в виде
    отдельного файла ``<key>.enc`` — JSON-блоба AES-256-GCM, ключ которого
    зашифрован открытым ключом владельца (см. crypto_core).
  * Индексная база (SQLite) тоже шифруется целиком: перед каждой операцией
    она расшифровывается в память и обратно сохраняется уже зашифрованной
    (ключ базы = производный от MASTER_KEY через HKDF).
  * На диске нет ни одного файла в открытом виде.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto_core import b64d, b64e, decrypt_file_bytes, encrypt_file_bytes


class EncryptedFileStore:
    """Хранилище «ключ → зашифрованный blob» в каталоге DATA_DIR."""

    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir)
        self.files_dir = self.data_dir / "files"
        self.db_dir = self.data_dir / "db"
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self.db_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------- объектные файлы ---------------------------- #
    def _path(self, key: str) -> Path:
        safe = base64.urlsafe_b64encode(key.encode()).decode().rstrip("=")
        return self.files_dir / f"{safe}.enc"

    def put_encrypted(self, key: str, plaintext: bytes, recipient_pub_pem: str) -> None:
        blob = encrypt_file_bytes(plaintext, recipient_pub_pem)
        self._path(key).write_text(json.dumps(blob), encoding="utf-8")

    def get_decrypted(self, key: str, private_key_pem: str, passphrase: bytes) -> bytes:
        p = self._path(key)
        if not p.exists():
            raise FileNotFoundError(key)
        blob = json.loads(p.read_text(encoding="utf-8"))
        return decrypt_file_bytes(blob, private_key_pem, passphrase)

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def delete(self, key: str) -> None:
        p = self._path(key)
        if p.exists():
            p.unlink()


class EncryptedSQLite:
    """Полностью зашифрованная SQLite-база.

    Файл ``index.db.enc`` на диске — AES-256-GCM blob всей базы.
    При открытии база расшифровывается во временный файл (в RAM-диске /tmp
    с правами 0600), по окончании транзакции переносится обратно зашифрованной.
    Ключ выводится из MASTER_KEY через HKDF-SHA256.
    """

    def __init__(self, db_name: str, master_key: bytes, store: EncryptedFileStore):
        self.store = store
        self.db_path = store.db_dir / f"{db_name}.db.enc"
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=b"furrynet-db-v1", info=db_name.encode())
        self._key = hkdf.derive(master_key)
        self._tmp: str | None = None
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------ #
    def _load(self) -> sqlite3.Connection:
        tmp = tempfile.NamedTemporaryFile(prefix="fn-db-", delete=False)
        tmp.close()
        os.chmod(tmp.name, 0o600)
        if self.db_path.exists():
            raw = self.db_path.read_bytes()
            nonce, ct = raw[:12], raw[12:]
            plain = AESGCM(self._key).decrypt(nonce, ct, None)
            with open(tmp.name, "wb") as f:
                f.write(plain)
        else:
            sqlite3.connect(tmp.name).close()  # создать пустую базу
        conn = sqlite3.connect(tmp.name, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        self._tmp, self._conn = tmp.name, conn
        return conn

    def _flush(self) -> None:
        assert self._conn is not None and self._tmp is not None
        self._conn.commit()
        self._conn.close()
        with open(self._tmp, "rb") as f:
            plain = f.read()
        nonce = os.urandom(12)
        ct = AESGCM(self._key).encrypt(nonce, plain, None)
        tmp_out = self.db_path.with_suffix(".tmp")
        tmp_out.write_bytes(nonce + ct)
        os.replace(tmp_out, self.db_path)
        os.unlink(self._tmp)
        self._conn, self._tmp = None, None

    @contextmanager
    def transaction(self):
        conn = self._load()
        try:
            yield conn
        finally:
            self._flush()

    def query(self, sql: str, params: tuple = ()):
        """Только чтение — не переписывает файл базы."""
        conn = self._load()
        try:
            rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            self._conn.close()
            os.unlink(self._tmp)
            self._conn, self._tmp = None, None
        return rows

    def execute(self, sql: str, params: tuple = ()):
        with self.transaction() as conn:
            cur = conn.execute(sql, params)
            return cur.lastrowid
