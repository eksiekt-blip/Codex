import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DB_PATH", str(ROOT / "mitsumori.db")))
SESSION_COOKIE = "mitsumori_session"
SESSION_DAYS = 30
MAX_BODY = 2 * 1024 * 1024
RATE_LIMIT = {}

def now_iso(): return datetime.now(timezone.utc).isoformat()
def default_state(company_name):
    return {"settings":{"companyName":company_name or "","companyPhone":"","companyAddress":""},"customers":[],"estimates":[]}

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL, salt TEXT NOT NULL, state_json TEXT NOT NULL,
          plan TEXT NOT NULL DEFAULT 'trial', trial_ends_at TEXT NOT NULL,
          billing_ref TEXT UNIQUE, stripe_customer_id TEXT, stripe_subscription_id TEXT,
          created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
        """)
        columns={row[1] for row in db.execute("PRAGMA table_info(users)")}
        for name,sql in [("stripe_customer_id","ALTER TABLE users ADD COLUMN stripe_customer_id TEXT"),("stripe_subscription_id","ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT"),("billing_ref","ALTER TABLE users ADD COLUMN billing_ref TEXT")]:
            if name not in columns: db.execute(sql)
        for row in db.execute("SELECT id FROM users WHERE billing_ref IS NULL OR billing_ref = ''").fetchall():
            db.execute("UPDATE users SET billing_ref=? WHERE id=?",(secrets.token_hex(16),row[0]))

def hash_password(password,salt=None):
    salt_bytes=bytes.fromhex(salt) if salt else secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt_bytes,310000)
    return digest.hex(),salt_bytes.hex()
def token_hash(token): return hashlib.sha256(token.encode()).hexdigest()

class AppHandler(SimpleHTTPRequestHandler):
    server_version="MitsumoriPocket/1.0"
    def __init__(self,*args,**kwargs): super().__init__(*args,directory=str(ROOT),**kwargs)
    def end_headers(self):
        self.send_header("X-Content-Type-Options","nosniff"); self.send_header("X-Frame-Options","DENY")
        self.send_header("Referrer-Policy","same-origin"); self.send_header("Permissions-Policy","camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://buy.stripe.com")
        self.send_header("Cache-Control","no-store" if self.path.startswith("/api/") else "no-cache"); super().end_headers()
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/health": return self.json_response(200,{"status":"ok"})
        if path=="/api/state": return self.get_state()
        if path.startswith("/api/"): return self.json_response(404,{"error":"APIが見つかりません。"})
        if path in ("/server.py","/README.txt") or path.startswith("/mitsumori.db") or path.startswith("/__pycache__/"): return self.send_error(404)
        if path=="/": self.path="/index.html"
        return super().do_GET()
    def do_POST(self):
        path=urlparse(self.path).path
        routes={"/api/auth/register":self.register,"/api/auth/login":self.login,"/api/auth/logout":self.logout,"/api/billing/checkout":self.checkout,"/api/stripe/webhook":self.stripe_webhook}
        return routes[path]() if path in routes else self.json_response(404,{"error":"APIが見つかりません。"})
    def do_PUT(self):
        return self.put_state() if urlparse(self.path).path=="/api/state" else self.json_response(404,{"error":"APIが見つかりません。"})
    def read_json(self):
        length=int(self.headers.get("Content-Length","0"))
        if length>MAX_BODY: raise ValueError("データ量が大きすぎます。")
        try: return json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError,UnicodeDecodeError): raise ValueError("JSON形式が不正です。")
    def rate_limited(self,key,limit=10,window=300):
        now=time.time(); attempts=[x for x in RATE_LIMIT.get(key,[]) if now-x<window]
        if len(attempts)>=limit: RATE_LIMIT[key]=attempts; return True
        attempts.append(now); RATE_LIMIT[key]=attempts; return False
    def json_response(self,status,payload,cookie=None):
        body=json.dumps(payload,ensure_ascii=False).encode(); self.send_response(status)
        self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(body)))
        if cookie: self.send_header("Set-Cookie",cookie)
        self.end_headers(); self.wfile.write(body)
    def current_user(self):
        cookie=SimpleCookie(); cookie.load(self.headers.get("Cookie","")); morsel=cookie.get(SESSION_COOKIE)
        if not morsel: return None
        with sqlite3.connect(DB_PATH) as db:
            db.row_factory=sqlite3.Row
            row=db.execute("SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?",(token_hash(morsel.value),now_iso())).fetchone()
            return dict(row) if row else None
    def create_session(self,db,user_id):
        token=secrets.token_urlsafe(32); expires=datetime.now(timezone.utc)+timedelta(days=SESSION_DAYS)
        db.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",(token_hash(token),user_id,expires.isoformat()))
        secure="; Secure" if os.environ.get("COOKIE_SECURE","0")=="1" else ""
        return f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_DAYS*86400}{secure}"
    def register(self):
        if self.rate_limited(f"register:{self.client_address[0]}",6,600): return self.json_response(429,{"error":"しばらく待ってから再度お試しください。"})
        try: p=self.read_json()
        except ValueError as e: return self.json_response(400,{"error":str(e)})
        email=str(p.get("email","")).strip().lower(); password=str(p.get("password","")); company=str(p.get("companyName","")).strip()
        if "@" not in email or len(email)>254: return self.json_response(400,{"error":"メールアドレスを確認してください。"})
        if len(password)<8: return self.json_response(400,{"error":"パスワードは8文字以上にしてください。"})
        digest,salt=hash_password(password); trial_end=datetime.now(timezone.utc)+timedelta(days=14)
        try:
            with sqlite3.connect(DB_PATH) as db:
                cur=db.execute("INSERT INTO users(email,password_hash,salt,state_json,trial_ends_at,billing_ref,created_at) VALUES(?,?,?,?,?,?,?)",(email,digest,salt,json.dumps(default_state(company),ensure_ascii=False),trial_end.isoformat(),secrets.token_hex(16),now_iso()))
                cookie=self.create_session(db,cur.lastrowid)
        except sqlite3.IntegrityError: return self.json_response(409,{"error":"このメールアドレスは登録済みです。"})
        return self.json_response(201,{"ok":True},cookie)
    def login(self):
        if self.rate_limited(f"login:{self.client_address[0]}",12,600): return self.json_response(429,{"error":"しばらく待ってから再度お試しください。"})
        try: p=self.read_json()
        except ValueError as e: return self.json_response(400,{"error":str(e)})
        email=str(p.get("email","")).strip().lower(); password=str(p.get("password",""))
        with sqlite3.connect(DB_PATH) as db:
            db.row_factory=sqlite3.Row; user=db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
            if not user: return self.json_response(401,{"error":"メールアドレスまたはパスワードが違います。"})
            candidate,_=hash_password(password,user["salt"])
            if not hmac.compare_digest(candidate,user["password_hash"]): return self.json_response(401,{"error":"メールアドレスまたはパスワードが違います。"})
            cookie=self.create_session(db,user["id"])
        return self.json_response(200,{"ok":True},cookie)
    def logout(self):
        cookie=SimpleCookie(); cookie.load(self.headers.get("Cookie","")); morsel=cookie.get(SESSION_COOKIE)
        if morsel:
            with sqlite3.connect(DB_PATH) as db: db.execute("DELETE FROM sessions WHERE token_hash=?",(token_hash(morsel.value),))
        secure="; Secure" if os.environ.get("COOKIE_SECURE","0")=="1" else ""
        return self.json_response(200,{"ok":True},f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}")
    def get_state(self):
        user=self.current_user()
        if not user: return self.json_response(401,{"error":"ログインが必要です。"})
        state=json.loads(user["state_json"]); state["account"]={"email":user["email"],"plan":user["plan"],"trialEndsAt":user["trial_ends_at"]}
        return self.json_response(200,state)
    def put_state(self):
        user=self.current_user()
        if not user: return self.json_response(401,{"error":"ログインが必要です。"})
        if user["plan"]!="standard" and datetime.fromisoformat(user["trial_ends_at"])<=datetime.now(timezone.utc): return self.json_response(402,{"error":"無料期間が終了しました。スタンダードプランへお申し込みください。"})
        try: p=self.read_json()
        except ValueError as e: return self.json_response(400,{"error":str(e)})
        state={"settings":p.get("settings",{}),"customers":p.get("customers",[]),"estimates":p.get("estimates",[])}
        if not isinstance(state["customers"],list) or not isinstance(state["estimates"],list): return self.json_response(400,{"error":"保存データが不正です。"})
        with sqlite3.connect(DB_PATH) as db: db.execute("UPDATE users SET state_json=? WHERE id=?",(json.dumps(state,ensure_ascii=False),user["id"]))
        state["account"]={"email":user["email"],"plan":user["plan"],"trialEndsAt":user["trial_ends_at"]}; return self.json_response(200,state)
    def checkout(self):
        user=self.current_user()
        if not user: return self.json_response(401,{"error":"ログインが必要です。"})
        link=os.environ.get("STRIPE_PAYMENT_LINK","").strip()
        if not link: return self.json_response(503,{"error":"決済ページは未接続です。公開時にStripeの決済リンクを設定してください。"})
        parsed=urlparse(link); query=dict(parse_qsl(parsed.query,keep_blank_values=True)); query["client_reference_id"]=user["billing_ref"]
        return self.json_response(200,{"url":urlunparse(parsed._replace(query=urlencode(query)))})
    def stripe_webhook(self):
        secret=os.environ.get("STRIPE_WEBHOOK_SECRET","").strip()
        if not secret: return self.json_response(503,{"error":"Webhookが未設定です。"})
        length=int(self.headers.get("Content-Length","0")); raw=self.rfile.read(length); parts={}
        for item in self.headers.get("Stripe-Signature","").split(","):
            if "=" in item:
                k,v=item.split("=",1); parts.setdefault(k,[]).append(v)
        try: timestamp=int(parts.get("t",["0"])[0])
        except ValueError: timestamp=0
        expected=hmac.new(secret.encode(),f"{timestamp}.".encode()+raw,hashlib.sha256).hexdigest()
        if abs(time.time()-timestamp)>300 or not any(hmac.compare_digest(expected,v) for v in parts.get("v1",[])): return self.json_response(400,{"error":"署名を確認できません。"})
        try: event=json.loads(raw)
        except json.JSONDecodeError: return self.json_response(400,{"error":"JSON形式が不正です。"})
        typ=event.get("type",""); obj=event.get("data",{}).get("object",{})
        with sqlite3.connect(DB_PATH) as db:
            if typ in ("checkout.session.completed","checkout.session.async_payment_succeeded"):
                ref=str(obj.get("client_reference_id",""))
                if ref: db.execute("UPDATE users SET plan='standard',stripe_customer_id=?,stripe_subscription_id=? WHERE billing_ref=?",(obj.get("customer"),obj.get("subscription"),ref))
            elif typ=="customer.subscription.deleted": db.execute("UPDATE users SET plan='inactive' WHERE stripe_subscription_id=? OR stripe_customer_id=?",(obj.get("id"),obj.get("customer")))
            elif typ=="invoice.payment_failed": db.execute("UPDATE users SET plan='past_due' WHERE stripe_customer_id=?",(obj.get("customer"),))
            elif typ=="invoice.paid": db.execute("UPDATE users SET plan='standard' WHERE stripe_customer_id=?",(obj.get("customer"),))
        return self.json_response(200,{"received":True})

if __name__=="__main__":
    DB_PATH.parent.mkdir(parents=True,exist_ok=True); init_db()
    host=os.environ.get("HOST","127.0.0.1"); port=int(os.environ.get("PORT","8765"))
    print(f"Mitsumori Pocket: http://{host}:{port}"); ThreadingHTTPServer((host,port),AppHandler).serve_forever()
