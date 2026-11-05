"""
test_e2e.py — сквозной тест всех требований FurryNet.

  1. Строгая проверка возраста (несовершеннолетним отказано, документ с HMAC).
  2. Защита от детей: настройки видимости пользователей и контента.
  3. Все файлы на сервере зашифрованы (проверка содержимого DATA_DIR).
  4. Взаимное доверие → обмен публичными ключами → виден аватар и профиль.

Запуск: python test_e2e.py
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import tempfile

os.environ["FURRYNET_DATA"] = tempfile.mkdtemp(prefix="fn-test-")
os.environ["FURRYNET_ADMIN_SECRET"] = "admin-secret"

from fastapi.testclient import TestClient  # noqa: E402
import app as appmod                        # noqa: E402

client = TestClient(appmod.app)

PNG = base64.b64encode(b"\x89PNG\r\n\x1a\nFAKE-AVATAR-DATA").decode()


def login(username: str, password: str, birth: str):
    c = TestClient(appmod.app)
    r = c.post("/register", data={"username": username, "password": password,
                                  "birth_date": birth})
    assert r.status_code == 200, r.text
    r = c.post("/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return c, r.json()["uid"] if False else None


def verify(c, uid):
    """Проходит строгую верификацию через демо-провайдера документов."""
    doc = client.post("/admin/issue_document",
                      data={"uid": uid, "admin_secret": "admin-secret"})
    assert doc.status_code == 200, doc.text
    r = c.post("/verify", data={"document_code": doc.json()["document_code"]})
    assert r.status_code == 200, r.text
    return r.json()


def register_only(username, password, birth):
    r = client.post("/register", data={"username": username,
                                       "password": password,
                                       "birth_date": birth})
    assert r.status_code == 200, r.text
    return r.json()["uid"]


results = []

# ---------------------------------------------------------------- regression 0
alice_uid = register_only("alice", "Alice!12345", "1995-04-01")
bob_uid = register_only("bob", "Bob!12345678", "1990-01-01")
kid_uid = register_only("kid", "Kid!12345678", "2012-01-01")
toddler = client.post("/register", data={"username": "tiny", "password": "x"*12,
                                         "birth_date": "2020-01-01"})
assert toddler.status_code == 451
results.append(("Отказ в регистрации младше 13 лет (COPPA)", True))

# ---------------------------------------------------------------- 1. возраст
ca = TestClient(appmod.app); ca.post("/login", data={"username": "alice", "password": "Alice!12345"})
cb = TestClient(appmod.app); cb.post("/login", data={"username": "bob", "password": "Bob!12345678"})
ck = TestClient(appmod.app); ck.post("/login", data={"username": "kid", "password": "Kid!12345678"})

ok_a = verify(ca, alice_uid)
ok_b = verify(cb, bob_uid)
doc_kid = client.post("/admin/issue_document",
                      data={"uid": kid_uid, "admin_secret": "admin-secret"})
assert doc_kid.status_code == 400   # совершеннолетие не подтверждается
bad_doc = ck.post("/verify", data={"document_code": "ADULT-2026-99.deadbeef"})
assert bad_doc.status_code == 400   # поддельная подпись отклонена
nsfw_as_kid = ck.post("/posts", data={"text": "bad", "rating": "nsfw"})
assert nsfw_as_kid.status_code == 403
exch_as_kid = ck.post("/exchange_keys", data={"username": "alice"})
assert exch_as_kid.status_code == 403
results.append(("Строгая проверка возраста: minors заблокированы в 18+,"
                " поддельный документ отклонён", True))

# ---------------------------------------------------------------- 2. видимость
r = ca.post("/settings/visibility", data={"value": "mutual_trust"})
assert r.status_code == 200
r = ca.post("/profile/publish", data={"bio": "Я Алиса, арт-фури 🦊", "avatar_png_b64": PNG})
assert r.status_code == 200 and r.json()["encrypted_for_users"] >= 1

prof_anon = client.get("/profile/alice")
assert prof_anon.status_code == 403 and "anonymous" in prof_anon.text
prof_kid = ck.get("/profile/alice")
assert prof_kid.status_code == 403 and "age_verification_required" in prof_kid.text
prof_bob = cb.get("/profile/alice")
assert prof_bob.status_code == 403 and "no_mutual_trust" in prof_bob.text
results.append(("Защита от детей: закрытый профиль недоступен анонимам,"
                " несовершеннолетним и без взаимного доверия", True))

# ---------------------------------------------------------------- 4. ключи
t1 = ca.post("/trust", data={"username": "bob"}); assert t1.json()["mutual"] is False
t2 = cb.post("/trust", data={"username": "alice"}); assert t2.json()["mutual"] is True
before = cb.get("/profile/alice")
assert before.status_code == 403 and "keys_not_exchanged" in before.text
e1 = ca.post("/exchange_keys", data={"username": "bob"})
assert e1.status_code == 200, e1.text
after = cb.get("/profile/alice")
assert after.status_code == 200, after.text
body = after.json()
assert body["access_reason"] == "mutual_trust_keys"
assert body["bio"] == "Я Алиса, арт-фури 🦊"
assert body["avatar_png_b64"] == PNG
# и в обратную сторону
cb.post("/profile/publish", data={"bio": "Боб-волк 🐺", "avatar_png_b64": PNG})
rev = ca.get("/profile/bob")
assert rev.status_code == 200 and rev.json()["bio"] == "Боб-волк 🐺"
results.append(("Взаимное доверие + обмен публичными ключами → "
                "аватар и профиль видны обеим сторонам", True))

# feed: nsfw post from verified adult visible to mutual-trust partner
p = ca.post("/posts", data={"text": "18+ артворк", "rating": "nsfw"})
assert p.status_code == 200
feed_b = cb.get("/feed", params={"include_nsfw": True}).json()
assert any(i["text"] == "18+ артворк" for i in feed_b)
feed_k = ck.get("/feed", params={"include_nsfw": True})
assert feed_k.status_code == 403
results.append(("Лента NSFW: доступна проверенным взрослым с доступом к автору, "
                "закрыта несовершеннолетним", True))

# ---------------------------------------------------------------- 3. шифрование
data_dir = appmod.DATA_DIR
LEAK_MARKERS = [b"Alice!12345", "Я Алиса".encode(), b"\x89PNG",
                b"BEGIN RSA PRIVATE KEY", "18+ артворк".encode(),
                "Боб-волк".encode(), "art-фури".encode()]
leaks = []
for root, _, files in os.walk(data_dir):
    for fn in files:
        raw = open(os.path.join(root, fn), "rb").read()
        if any(m in raw for m in LEAK_MARKERS):
            leaks.append(os.path.join(root, fn))
assert not leaks, f"Найдены открытые данные в файлах: {leaks}"
enc_files = [f for f in os.listdir(data_dir / "files")]
assert all(f.endswith(".enc") or f.endswith(".enc.json") for f in enc_files)
db_file = data_dir / "db" / "index.db.enc"
assert db_file.exists() and open(db_file, "rb").read(16)[:10] != b"SQLite for"
results.append(("Все файлы на сервере зашифрованы: ни в одном нет открытых "
                "био/аватара/постов/ключей; база не читается как SQLite", True))

shutil.rmtree(os.environ["FURRYNET_DATA"], ignore_errors=True)

print("\n===== РЕЗУЛЬТАТЫ =====")
for name, ok in results:
    print(("✅ " if ok else "❌ ") + name)
print(f"\nВсе проверки пройдены: {all(ok for _, ok in results)}")
