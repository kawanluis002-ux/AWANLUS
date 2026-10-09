# ============================================================
# LUCRA.AI — EXECUTIVE VISION
# MAIN.PY — PARTE 1 DE 2
# ============================================================

import os
import io
import re
import json
import sqlite3
import secrets
import hashlib
import smtplib
import unicodedata
import time
import threading
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict, deque
from email.message import EmailMessage

import pandas as pd

from flask import (
    Flask,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    send_file,
    send_from_directory,
    render_template_string,
    abort,
)

from werkzeug.utils import secure_filename


# ============================================================
# GPT - TROCAR AQUI - CONFIGURAÇÕES VISUAIS
# ============================================================
LOGO_PWA = "/icon.png"
LOGO_SITE = "/logo-dourada.png"

NOME_APP = "LUCRA.AI"

COR_PRINCIPAL = "#D4AF37"
COR_DOURADO_CLARO = "#FFF4A3"
COR_PRETO = "#050505"
COR_BRANCO = "#FFFFFF"
COR_FUNDO = "#F5F5F5"

# ============================================================
# CONFIGURAÇÕES PRINCIPAIS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = Path(
    os.environ.get(
        "LUCRA_DATA_DIR",
        str(BASE_DIR),
    )
).expanduser().resolve()

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

DATABASE = DATA_DIR / "lucra.db"

UPLOAD_FOLDER = DATA_DIR / "uploads"

DOWNLOAD_FOLDER = BASE_DIR / "downloads"

STATIC_IMAGE_FOLDER = (
    BASE_DIR
    / "static"
    / "images"
)

UPLOAD_FOLDER.mkdir(
    parents=True,
    exist_ok=True,
)

DOWNLOAD_FOLDER.mkdir(
    parents=True,
    exist_ok=True,
)

(DOWNLOAD_FOLDER / "android").mkdir(
    parents=True,
    exist_ok=True,
)

(DOWNLOAD_FOLDER / "windows").mkdir(
    parents=True,
    exist_ok=True,
)

STATIC_IMAGE_FOLDER.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# ADMIN
# ============================================================

ADMIN_EMAIL = os.environ.get(
    "LUCRA_ADMIN_EMAIL",
    "kawanluisbezerrasilvaa@gmail.com",
).strip().lower()

ADMIN_PASSWORD = os.environ.get(
    "LUCRA_ADMIN_PASSWORD",
    "Klz@1985",
)


# ============================================================
# ENVIO DE E-MAIL / RECUPERAÇÃO DE SENHA
# ============================================================

SMTP_HOST = os.environ.get(
    "LUCRA_SMTP_HOST",
    "",
).strip()

try:
    SMTP_PORT = int(
        os.environ.get(
            "LUCRA_SMTP_PORT",
            "587",
        ).strip()
        or "587"
    )
except ValueError:
    SMTP_PORT = 587

SMTP_USER = os.environ.get(
    "LUCRA_SMTP_USER",
    "",
).strip()

SMTP_PASSWORD = os.environ.get(
    "LUCRA_SMTP_PASSWORD",
    "",
)

SMTP_FROM = (
    os.environ.get(
        "LUCRA_SMTP_FROM",
        "",
    ).strip()
    or SMTP_USER
)

SMTP_SSL = (
    os.environ.get(
        "LUCRA_SMTP_SSL",
        "1" if SMTP_PORT == 465 else "0",
    ).strip()
    == "1"
)

RESET_CODE_MINUTES = 10

RESET_MAX_ATTEMPTS = 5

RESET_RESEND_SECONDS = 60

RESET_GRANT_MINUTES = 10


# ============================================================
# APLICAÇÃO
# ============================================================

app = Flask(
    __name__,
)

configured_secret = os.environ.get(
    "LUCRA_SECRET_KEY",
    "",
).strip()

SECRET_FILE = DATA_DIR / ".lucra_secret"

if configured_secret:
    secret_value = configured_secret

elif SECRET_FILE.exists():
    secret_value = (
        SECRET_FILE
        .read_text(
            encoding="utf-8"
        )
        .strip()
    )

    if not secret_value:
        secret_value = secrets.token_urlsafe(64)

        SECRET_FILE.write_text(
            secret_value,
            encoding="utf-8",
        )

else:
    secret_value = secrets.token_urlsafe(64)

    SECRET_FILE.write_text(
        secret_value,
        encoding="utf-8",
    )


app.secret_key = secret_value

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get(
            "LUCRA_HTTPS",
            "0",
        )
        == "1"
    ),
    MAX_CONTENT_LENGTH=100 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(
        days=7
    ),
)


# ============================================================
# ARQUIVOS ACEITOS
# ============================================================

ALLOWED_EXTENSIONS = {
    "csv",
    "tsv",
    "txt",
    "xlsx",
    "xlsm",
    "xls",
}

SHEET_ACCEPT = (
    ".csv,.tsv,.txt,.xls,.xlsx,.xlsm,"
    "text/csv,text/plain,text/tab-separated-values,"
    "application/vnd.ms-excel,"
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,"
    "application/vnd.ms-excel.sheet.macroEnabled.12"
)

MAX_FILE_SIZE = (
    10 * 1024 * 1024
)

MAX_CHAT_FILES = 200


# ============================================================
# BANCO DE DADOS
# ============================================================

def db():
    connection = sqlite3.connect(
        str(DATABASE),
        timeout=20,
    )

    connection.row_factory = sqlite3.Row

    return connection


def hash_password(password):
    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        210000,
    )

    return (
        salt.hex()
        + ":"
        + password_hash.hex()
    )


def verify_password(
    password,
    stored,
):
    try:
        salt_hex, hash_hex = stored.split(
            ":",
            1,
        )

        salt = bytes.fromhex(
            salt_hex
        )

        calculated = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            210000,
        ).hex()

        return secrets.compare_digest(
            calculated,
            hash_hex,
        )

    except Exception:
        return False


def table_columns(
    connection,
    table_name,
):
    rows = connection.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    return {
        row[1]
        for row in rows
    }


def init_db():
    connection = db()

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            password_hash TEXT NOT NULL,
            approved INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            identifier TEXT,
            login_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS datasets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            created_at TEXT NOT NULL,
            data_json TEXT,
            filepath TEXT,
            relative_path TEXT,
            source_type TEXT DEFAULT 'file',
            row_count INTEGER DEFAULT 0,
            columns_json TEXT DEFAULT '[]',
            analysis_json TEXT DEFAULT '{}',
            sha256 TEXT DEFAULT ''
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS source_roots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            root_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, root_name)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            message TEXT,
            response TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            code_hash TEXT NOT NULL DEFAULT '',
            channel TEXT NOT NULL DEFAULT 'email',
            attempts INTEGER DEFAULT 0,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            grant_hash TEXT DEFAULT ''
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    columns = table_columns(
        connection,
        "datasets",
    )

    migrations = {
        "filepath": "TEXT",
        "relative_path": "TEXT",
        "source_type": "TEXT DEFAULT 'file'",
        "row_count": "INTEGER DEFAULT 0",
        "columns_json": "TEXT DEFAULT '[]'",
        "analysis_json": "TEXT DEFAULT '{}'",
        "sha256": "TEXT DEFAULT ''",
    }

    for name, definition in migrations.items():

        if name not in columns:

            cursor.execute(
                f"""
                ALTER TABLE datasets
                ADD COLUMN {name} {definition}
                """
            )

    extra_migrations = {
        "users": {
            "revoked": "INTEGER DEFAULT 0",
        },
        "chat_history": {
            "conversation_id": "INTEGER",
            "response_summary": "TEXT DEFAULT ''",
        },
    }

    for table_name, table_migrations in extra_migrations.items():

        existing_columns = table_columns(
            connection,
            table_name,
        )

        for name, definition in table_migrations.items():

            if name not in existing_columns:

                cursor.execute(
                    f"""
                    ALTER TABLE {table_name}
                    ADD COLUMN {name} {definition}
                    """
                )

    orphan_users = cursor.execute(
        """
        SELECT DISTINCT user_id
        FROM chat_history
        WHERE conversation_id IS NULL
        AND user_id IS NOT NULL
        """
    ).fetchall()

    for orphan in orphan_users:

        stamp = datetime.now().isoformat(
            timespec="seconds"
        )

        cursor.execute(
            """
            INSERT INTO conversations
            (
                user_id,
                title,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                orphan[0],
                "Conversas anteriores",
                stamp,
                stamp,
            ),
        )

        cursor.execute(
            """
            UPDATE chat_history
            SET conversation_id = ?
            WHERE user_id = ?
            AND conversation_id IS NULL
            """,
            (
                cursor.lastrowid,
                orphan[0],
            ),
        )

    admin = cursor.execute(
        """
        SELECT *
        FROM users
        WHERE lower(email) = ?
        ORDER BY id
        LIMIT 1
        """,
        (
            ADMIN_EMAIL,
        ),
    ).fetchone()

    if not admin:

        admin = cursor.execute(
            """
            SELECT *
            FROM users
            WHERE is_admin = 1
            ORDER BY id
            LIMIT 1
            """
        ).fetchone()

    if admin:

        admin_hash = admin["password_hash"] or ""

        if not verify_password(
            ADMIN_PASSWORD,
            admin_hash,
        ):
            admin_hash = hash_password(
                ADMIN_PASSWORD
            )

        cursor.execute(
            """
            UPDATE users
            SET
                username = ?,
                email = ?,
                password_hash = ?,
                approved = 1,
                is_admin = 1,
                revoked = 0
            WHERE id = ?
            """,
            (
                "Kawan ADM",
                ADMIN_EMAIL,
                admin_hash,
                admin["id"],
            ),
        )

        admin_id = admin["id"]

    else:

        cursor.execute(
            """
            INSERT INTO users
            (
                username,
                email,
                phone,
                password_hash,
                approved,
                is_admin,
                created_at
            )
            VALUES (?, ?, ?, ?, 1, 1, ?)
            """,
            (
                "Kawan ADM",
                ADMIN_EMAIL,
                "",
                hash_password(
                    ADMIN_PASSWORD
                ),
                datetime.now().isoformat(
                    timespec="seconds"
                ),
            ),
        )

        admin_id = cursor.lastrowid

    cursor.execute(
        """
        UPDATE users
        SET is_admin = 0
        WHERE is_admin = 1
        AND id <> ?
        """,
        (
            admin_id,
        ),
    )

    connection.commit()

    connection.close()


init_db()


# ============================================================
# SESSÃO / AUTENTICAÇÃO
# ============================================================

KICKED_MESSAGE = "Você foi desconectado da LUCRA IA!"


def ua_fingerprint():

    agent = request.headers.get(
        "User-Agent",
        "",
    )

    return hashlib.sha256(
        agent.encode(
            "utf-8",
            "ignore",
        )
    ).hexdigest()[:32]


def kicked_response():

    if (
        request.path.startswith("/api/")
        or request.path == "/upload"
        or request.is_json
    ):

        return jsonify(
            {
                "ok": False,
                "kicked": True,
                "error": KICKED_MESSAGE,
            }
        ), 401

    return redirect(
        url_for(
            "login_page",
            kicked=1,
        )
    )


def current_user():

    user_id = session.get(
        "user_id"
    )

    if not user_id:
        return None

    stored_fingerprint = session.get(
        "ua"
    )

    if stored_fingerprint and not secrets.compare_digest(
        stored_fingerprint,
        ua_fingerprint(),
    ):
        session.clear()
        return None

    connection = db()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (
            user_id,
        ),
    ).fetchone()

    connection.close()

    return user


def login_required(function):

    @wraps(function)
    def wrapper(
        *args,
        **kwargs,
    ):

        user = current_user()

        if not user:

            removed = bool(
                session.get("user_id")
            )

            session.clear()

            if removed:
                return kicked_response()

            return redirect(
                url_for(
                    "login_page"
                )
            )

        if not int(
            user["approved"]
        ):
            session.clear()

            return kicked_response()

        return function(
            *args,
            **kwargs,
        )

    return wrapper


def admin_required(function):

    @wraps(function)
    def wrapper(
        *args,
        **kwargs,
    ):

        user = current_user()

        if (
            not user
            or not int(
                user["is_admin"]
            )
        ):
            return (
                "Acesso negado.",
                403,
            )

        return function(
            *args,
            **kwargs,
        )

    return wrapper


# ============================================================
# IDENTIFICAÇÃO / ENVIO DE CÓDIGO
# ============================================================

def normalize_phone(value):

    return re.sub(
        r"\D",
        "",
        str(value or ""),
    )


def phones_match(
    first,
    second,
):

    a = normalize_phone(first)
    b = normalize_phone(second)

    if not a or not b:
        return False

    if a == b:
        return True

    shorter, longer = sorted(
        (a, b),
        key=len,
    )

    return (
        len(shorter) >= 10
        and longer.endswith(shorter)
    )


def find_users_by_phone(
    connection,
    phone,
    exclude_id=None,
):

    rows = connection.execute(
        """
        SELECT *
        FROM users
        WHERE phone IS NOT NULL
        AND phone <> ''
        """
    ).fetchall()

    return [
        row
        for row in rows
        if phones_match(
            row["phone"],
            phone,
        )
        and row["id"] != exclude_id
    ]


def find_user_by_identifier(
    connection,
    identifier,
):

    identifier = str(
        identifier or ""
    ).strip()

    if not identifier:
        return None

    if "@" in identifier:

        return connection.execute(
            """
            SELECT *
            FROM users
            WHERE lower(email) = ?
            """,
            (
                identifier.lower(),
            ),
        ).fetchone()

    if len(normalize_phone(identifier)) < 8:
        return None

    matches = find_users_by_phone(
        connection,
        identifier,
    )

    if len(matches) != 1:
        return None

    return matches[0]


def mask_email(email):

    try:
        name, domain = email.split(
            "@",
            1,
        )
    except ValueError:
        return "e-mail cadastrado"

    visible = name[:2] if len(name) > 2 else name[:1]

    return (
        visible
        + "***@"
        + domain
    )


def smtp_configured():

    return bool(
        SMTP_HOST
        and SMTP_FROM
    )


def send_email(
    to_address,
    subject,
    body,
):

    message = EmailMessage()

    message["Subject"] = subject
    message["From"] = SMTP_FROM
    message["To"] = to_address

    message.set_content(
        body
    )

    if SMTP_SSL:

        server = smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            timeout=20,
        )

    else:

        server = smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT,
            timeout=20,
        )

    try:

        if not SMTP_SSL:

            server.ehlo()

            if server.has_extn("starttls"):
                server.starttls()
                server.ehlo()

        if SMTP_USER:
            server.login(
                SMTP_USER,
                SMTP_PASSWORD,
            )

        server.send_message(
            message
        )

    finally:

        try:
            server.quit()
        except Exception:
            pass


def utc_now():

    return datetime.utcnow().replace(
        microsecond=0
    )


def grant_digest(grant):

    return hashlib.sha256(
        (
            app.secret_key
            + ":"
            + grant
        ).encode("utf-8")
    ).hexdigest()


# ============================================================
# CSRF
# ============================================================

def csrf_token():

    token = session.get(
        "csrf_token"
    )

    if not token:

        token = secrets.token_urlsafe(
            32
        )

        session["csrf_token"] = token

    return token


def check_csrf():

    sent = (
        request.headers.get(
            "X-CSRF-Token"
        )
        or request.form.get(
            "csrf_token"
        )
    )

    expected = session.get(
        "csrf_token"
    )

    if not expected or not sent:
        return False

    return secrets.compare_digest(
        expected,
        sent,
    )


# ============================================================
# PROTEÇÃO ANTI-INVASÃO
# ============================================================

TRUST_PROXY = (
    os.environ.get(
        "LUCRA_TRUST_PROXY",
        "0",
    ).strip()
    == "1"
)

RATE_LIMITS = {
    "login": (20, 15 * 60),
    "login_id": (6, 15 * 60),
    "register": (6, 60 * 60),
    "forgot": (12, 15 * 60),
    "forgot_verify": (30, 15 * 60),
    "chat": (40, 60),
    "upload": (80, 60),
}

RATE_LIMITED_ENDPOINTS = {
    "register": "register",
    "forgot_password": "forgot",
    "forgot_password_verify": "forgot_verify",
    "api_chat": "chat",
    "upload": "upload",
}

SUSPICIOUS_PATH_PARTS = (
    ".py",
    ".pyc",
    ".db",
    ".sqlite",
    ".env",
    ".git",
    ".idea",
    ".bak",
    ".sql",
    ".php",
    "lucra_secret",
    "wp-admin",
    "wp-login",
    "phpmyadmin",
    "cgi-bin",
    "/etc/passwd",
    "../",
    "..%2f",
    "%2e%2e",
)

SCANNER_AGENTS = (
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "acunetix",
    "wpscan",
    "dirbuster",
    "gobuster",
    "nuclei",
    "zgrab",
    "havij",
    "netsparker",
    "w3af",
    "hydra",
)

_rate_lock = threading.Lock()

_rate_events = defaultdict(deque)


def client_ip():

    if TRUST_PROXY:

        forwarded = request.headers.get(
            "X-Forwarded-For",
            "",
        )

        if forwarded:
            return forwarded.split(",")[0].strip()[:64]

    return (
        request.remote_addr
        or "0.0.0.0"
    )[:64]


def _prune_rate_events(
    events,
    window,
    now,
):

    while events and now - events[0] > window:
        events.popleft()


def rate_hit(
    bucket,
    key,
):

    limit, window = RATE_LIMITS[bucket]

    now = time.time()

    with _rate_lock:

        events = _rate_events[(bucket, key)]

        _prune_rate_events(
            events,
            window,
            now,
        )

        if len(events) >= limit:
            return True

        events.append(now)

        if len(_rate_events) > 5000:

            for stale_key in [
                item_key
                for item_key, item_events in _rate_events.items()
                if not item_events
                or now - item_events[-1] > 3600
            ]:
                _rate_events.pop(
                    stale_key,
                    None,
                )

    return False


def rate_blocked(
    bucket,
    key,
):

    limit, window = RATE_LIMITS[bucket]

    with _rate_lock:

        events = _rate_events.get(
            (bucket, key)
        )

        if not events:
            return False

        _prune_rate_events(
            events,
            window,
            time.time(),
        )

        return len(events) >= limit


def rate_clear(
    bucket,
    key,
):

    with _rate_lock:

        _rate_events.pop(
            (bucket, key),
            None,
        )


@app.before_request
def block_suspicious_requests():

    path = (
        request.full_path
        or request.path
        or ""
    ).lower()

    if any(
        part in path
        for part in SUSPICIOUS_PATH_PARTS
    ):
        abort(404)

    agent = (
        request.headers.get(
            "User-Agent"
        )
        or ""
    ).lower()

    if any(
        name in agent
        for name in SCANNER_AGENTS
    ):
        abort(403)

    if request.method != "POST":
        return None

    bucket = RATE_LIMITED_ENDPOINTS.get(
        request.endpoint
    )

    if not bucket:
        return None

    key = client_ip()

    if bucket == "chat" and session.get("user_id"):
        key += f":{session.get('user_id')}"

    if not rate_hit(
        bucket,
        key,
    ):
        return None

    message = (
        "🔒 Muitas solicitações em pouco tempo. "
        "Aguarde um pouco e tente novamente."
    )

    if (
        request.path.startswith("/api/")
        or request.path.startswith("/forgot-password")
        or request.path == "/upload"
        or request.is_json
    ):

        return jsonify(
            {
                "ok": False,
                "error": message,
            }
        ), 429

    return (
        message,
        429,
    )


@app.before_request
def protect_state_changes():

    if request.method not in {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }:
        return None

    if not check_csrf():

        if request.is_json:

            return jsonify(
                {
                    "ok": False,
                    "error": (
                        "Sessão de segurança inválida. "
                        "Recarregue a página."
                    ),
                }
            ), 400

        return (
            "Sessão de segurança inválida. "
            "Recarregue a página.",
            400,
        )

    return None


@app.context_processor
def inject_globals():

    return {
        "csrf_token": csrf_token,
        "logo_pwa": LOGO_PWA,
        "logo_site": LOGO_SITE,
        "nome_app": NOME_APP,
        "cor_principal": COR_PRINCIPAL,
        "cor_dourado_claro": COR_DOURADO_CLARO,
        "cor_preto": COR_PRETO,
        "cor_branco": COR_BRANCO,
        "cor_fundo": COR_FUNDO,
    }


# ============================================================
# NORMALIZAÇÃO
# ============================================================

def normalize(text):

    text = str(text)

    text = unicodedata.normalize(
        "NFKD",
        text,
    ).encode(
        "ascii",
        "ignore",
    ).decode(
        "ascii"
    )

    text = re.sub(
        r"\s+",
        " ",
        text.lower().strip(),
    )

    return text


def parse_number(value):

    if value is None:
        return 0.0

    if isinstance(
        value,
        (int, float),
    ) and not isinstance(
        value,
        bool,
    ):

        try:

            if pd.isna(value):
                return 0.0

        except Exception:
            pass

        return float(value)

    text = str(
        value
    ).strip()

    if not text:
        return 0.0

    negative = (
        text.startswith("(")
        and text.endswith(")")
    )

    text = text.replace(
        "R$",
        "",
    )

    text = text.replace(
        "r$",
        "",
    )

    text = text.replace(
        "%",
        "",
    )

    text = text.replace(
        " ",
        "",
    )

    if (
        ","
        in text
        and "."
        in text
    ):

        if text.rfind(",") > text.rfind("."):

            text = text.replace(
                ".",
                "",
            )

            text = text.replace(
                ",",
                ".",
            )

        else:

            text = text.replace(
                ",",
                "",
            )

    elif "," in text:

        if (
            len(
                text.split(",")[-1]
            )
            == 3
            and text.count(",") == 1
        ):

            text = text.replace(
                ",",
                "",
            )

        else:

            text = text.replace(
                ",",
                ".",
            )

    elif text.count(".") > 1:

        text = text.replace(
            ".",
            "",
        )

    text = re.sub(
        r"[^0-9.\-]",
        "",
        text,
    )

    try:

        number = float(
            text
        )

    except Exception:

        return 0.0

    if negative:
        number = -number

    return number


# ============================================================
# ALIAS DAS COLUNAS
# ============================================================

ALIASES = {

    "Receita Comercial": [
        "venda",
        "vendas",
        "receita",
        "faturamento",
        "faturamento total",
        "valor venda",
        "valor vendas",
        "valor receita",
        "receita comercial",
        "sales",
        "revenue",
    ],

    "Custo Operacional": [
        "custo",
        "custos",
        "despesa",
        "despesas",
        "custo operacional",
        "valor custo",
        "valor despesa",
        "cost",
        "expense",
    ],

    "Volume de Produção": [
        "producao",
        "produzido",
        "produzida",
        "quantidade produzida",
        "qtd producao",
        "volume producao",
        "volume de producao",
        "produção",
    ],

    "Ativo em Estoque": [
        "estoque",
        "estoques",
        "saldo estoque",
        "armazem",
        "almoxarifado",
        "ativo em estoque",
        "inventory",
    ],

    "Mix de Produtos": [
        "produto",
        "produtos",
        "mix",
        "mix produtos",
        "sku",
        "item",
    ],

    "Performance": [
        "performance",
        "desempenho",
        "resultado",
        "eficiencia",
        "eficiência",
    ],

    "Estratégia": [
        "estrategia",
        "planejamento",
        "meta",
        "objetivo",
        "target",
    ],
}


DATE_ALIASES = [
    "data",
    "date",
    "dt",
    "dia",
    "data venda",
    "data de venda",
    "data custo",
    "data producao",
    "data produção",
    "competencia",
    "competência",
    "periodo",
    "período",
    "mes",
    "mês",
]


def find_column(
    columns,
    aliases,
):

    normalized_columns = {
        normalize(column): column
        for column in columns
    }

    normalized_aliases = [
        normalize(alias)
        for alias in aliases
    ]

    for alias in normalized_aliases:

        if alias in normalized_columns:

            return normalized_columns[
                alias
            ]

    for column in columns:

        normalized_column = normalize(
            column
        )

        for alias in normalized_aliases:

            if (
                alias
                and alias
                in normalized_column
            ):
                return column

    return None


def find_date_column(columns):

    return find_column(
        columns,
        DATE_ALIASES,
    )


def parse_date_series(series):

    if pd.api.types.is_datetime64_any_dtype(
        series
    ):

        return pd.to_datetime(
            series,
            errors="coerce",
        )

    converted = pd.to_datetime(
        series,
        errors="coerce",
        dayfirst=True,
    )

    if converted.notna().sum() == 0:

        numeric = pd.to_numeric(
            series,
            errors="coerce",
        )

        if numeric.notna().sum() > 0:

            converted = pd.to_datetime(
                numeric,
                errors="coerce",
                unit="D",
                origin="1899-12-30",
            )

    return converted


# ============================================================
# ANÁLISE DE DATAFRAME
# ============================================================

def analyze_dataframe(
    dataframe,
):

    metrics = {
        "Valor Total": 0.0,
        "Receita Comercial": 0.0,
        "Custo Operacional": 0.0,
        "Volume de Produção": 0.0,
        "Ativo em Estoque": 0.0,
        "Mix de Produtos": 0.0,
        "Performance": 0.0,
        "Estratégia": 0.0,
    }

    numeric_columns = []

    for column in dataframe.columns:

        converted = (
            dataframe[column]
            .apply(parse_number)
        )

        if converted.abs().sum() > 0:

            numeric_columns.append(
                column
            )

    for metric_name, aliases in ALIASES.items():

        column = find_column(
            dataframe.columns,
            aliases,
        )

        if column:

            metrics[
                metric_name
            ] = float(
                dataframe[column]
                .apply(parse_number)
                .sum()
            )

    metrics["Valor Total"] = (
        metrics[
            "Receita Comercial"
        ]
        + metrics[
            "Custo Operacional"
        ]
        + metrics[
            "Ativo em Estoque"
        ]
    )

    if (
        metrics["Valor Total"]
        == 0
        and numeric_columns
    ):

        total = 0.0

        for column in numeric_columns:

            total += float(
                dataframe[column]
                .apply(parse_number)
                .sum()
            )

        metrics[
            "Valor Total"
        ] = total

    insights = []

    receita = metrics[
        "Receita Comercial"
    ]

    custo = metrics[
        "Custo Operacional"
    ]

    if receita == 0 and custo == 0:

        insights.append(
            "Nenhuma Receita Comercial ou "
            "Custo Operacional identificável nesta fonte."
        )

    elif receita > custo:

        insights.append(
            "A Receita Comercial identificada "
            "está acima do Custo Operacional."
        )

    elif custo > receita:

        insights.append(
            "ATENÇÃO: o Custo Operacional identificado "
            "está acima da Receita Comercial."
        )

    else:

        insights.append(
            "Receita Comercial e Custo Operacional "
            "foram identificados no mesmo nível."
        )

    if (
        metrics["Ativo em Estoque"]
        > receita
        > 0
    ):

        insights.append(
            "O Ativo em Estoque identificado "
            "está acima da Receita Comercial."
        )

    if (
        metrics["Volume de Produção"]
        == 0
    ):

        insights.append(
            "Não foi identificado Volume de Produção "
            "numérico válido nesta fonte."
        )

    return {
        "metrics": metrics,
        "insights": insights,
        "columns": [
            str(column)
            for column in dataframe.columns
        ],
        "rows": int(
            len(dataframe)
        ),
    }


# ============================================================
# ARQUIVOS
# ============================================================

def allowed_file(
    filename,
):

    suffix = (
        Path(filename)
        .suffix
        .lower()
        .lstrip(".")
    )

    return (
        suffix
        in ALLOWED_EXTENSIONS
    )


def secure_relative_path(
    relative_name,
):

    relative_name = str(
        relative_name or ""
    ).replace(
        "\\",
        "/",
    )

    parts = []

    for part in relative_name.split("/"):

        safe = secure_filename(
            part
        )

        if safe in {
            "",
            ".",
            "..",
        }:
            continue

        parts.append(
            safe
        )

    if not parts:
        return Path(
            "arquivo"
        )

    return Path(
        *parts
    )


def read_dataframe(
    file_path,
):

    suffix = (
        file_path
        .suffix
        .lower()
    )

    if suffix in {".csv", ".tsv", ".txt"}:

        last_error = None

        for encoding in (
            "utf-8-sig",
            "cp1252",
            "latin1",
        ):

            try:

                return pd.read_csv(
                    file_path,
                    encoding=encoding,
                    sep=None,
                    engine="python",
                )

            except Exception as exc:

                last_error = exc

        raise ValueError(
            f"CSV não pôde ser lido: {last_error}"
        )

    if suffix in {".xlsx", ".xlsm"}:

        return pd.read_excel(
            file_path,
            engine="openpyxl",
        )

    if suffix == ".xls":

        try:
            return pd.read_excel(
                file_path,
                engine="xlrd",
            )
        except Exception as exc:
            for encoding in (
                "utf-8-sig",
                "cp1252",
                "latin1",
            ):
                try:
                    return pd.read_csv(
                        file_path,
                        encoding=encoding,
                        sep=None,
                        engine="python",
                    )
                except Exception:
                    continue
            raise ValueError(
                f"XLS não pôde ser lido: {exc}"
            )

    raise ValueError(
        "Formato não suportado."
    )


def validate_spreadsheet_bytes(
    content,
    suffix,
):

    head = content[:8]

    if (
        head.startswith(b"MZ")
        or head.startswith(b"\x7fELF")
        or head.startswith(b"#!")
    ):
        raise ValueError(
            "Arquivo bloqueado pela proteção da LUCRA.AI."
        )

    if suffix in {
        ".xlsx",
        ".xlsm",
    }:

        if not content.startswith(
            b"PK\x03\x04"
        ):
            raise ValueError(
                "O arquivo não é uma planilha Excel válida."
            )

        return

    if suffix == ".xls":
        return

    sample = content[:8192]

    if b"\x00" in sample:
        raise ValueError(
            "O arquivo de texto enviado não é uma planilha válida."
        )

    lowered = sample.lower()

    if (
        b"<script" in lowered
        or b"<?php" in lowered
    ):
        raise ValueError(
            "Arquivo bloqueado pela proteção da LUCRA.AI."
        )


def file_sha256(
    file_path,
):

    digest = hashlib.sha256()

    with file_path.open(
        "rb"
    ) as handle:

        for chunk in iter(
            lambda: handle.read(
                1024 * 1024
            ),
            b"",
        ):

            digest.update(
                chunk
            )

    return digest.hexdigest()


def save_and_ingest(
    user_id,
    uploaded_file,
    source_type="file",
    relative_name=None,
):

    original_name = (
        uploaded_file.filename
        or "arquivo"
    )

    if not allowed_file(
        original_name
    ):

        raise ValueError(
            "Envie uma planilha CSV, TSV, TXT, XLS, XLSX ou XLSM."
        )

    content = uploaded_file.read()

    if len(content) > MAX_FILE_SIZE:

        raise ValueError(
            "Cada arquivo pode ter no máximo 10 MB."
        )

    if not content:

        raise ValueError(
            "O arquivo está vazio."
        )

    validate_spreadsheet_bytes(
        content,
        Path(
            original_name
        ).suffix.lower(),
    )

    relative = secure_relative_path(
        relative_name
        or original_name
    )

    if (
        relative.suffix.lower()
        not in {
            ".csv",
            ".tsv",
            ".txt",
            ".xlsx",
            ".xlsm",
            ".xls",
        }
    ):

        relative = relative.with_suffix(
            Path(
                original_name
            ).suffix.lower()
        )

    user_folder = (
        UPLOAD_FOLDER
        / str(user_id)
    )

    destination = (
        user_folder
        / relative
    )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    destination.write_bytes(
        content
    )

    try:

        dataframe = read_dataframe(
            destination
        )

    except Exception:

        try:
            destination.unlink(
                missing_ok=True
            )
        except Exception:
            pass

        raise

    dataframe.columns = [
        str(column).strip()
        for column in dataframe.columns
    ]

    analysis = analyze_dataframe(
        dataframe
    )

    sha = file_sha256(
        destination
    )

    connection = db()

    connection.execute(
        """
        INSERT INTO datasets
        (
            user_id,
            filename,
            created_at,
            data_json,
            filepath,
            relative_path,
            source_type,
            row_count,
            columns_json,
            analysis_json,
            sha256
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            original_name,
            datetime.now().isoformat(
                timespec="seconds"
            ),
            "{}",
            str(destination),
            relative.as_posix(),
            source_type,
            analysis["rows"],
            json.dumps(
                analysis["columns"],
                ensure_ascii=False,
            ),
            json.dumps(
                analysis,
                ensure_ascii=False,
            ),
            sha,
        ),
    )

    connection.commit()
    connection.close()

    return {
        "filename": original_name,
        "relative_path": relative.as_posix(),
        "rows": analysis["rows"],
        "analysis": analysis,
    }


def user_datasets(
    user_id,
):

    connection = db()

    rows = connection.execute(
        """
        SELECT *
        FROM datasets
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (
            user_id,
        ),
    ).fetchall()

    connection.close()

    return rows


def source_summary(
    user_id,
):

    rows = user_datasets(
        user_id
    )

    output = []

    for row in rows:

        try:

            analysis = json.loads(
                row["analysis_json"]
                or "{}"
            )

            metrics = analysis.get(
                "metrics",
                {},
            )

        except Exception:

            metrics = {}

        output.append(
            {
                "id": row["id"],
                "filename": row["filename"],
                "relative_path": (
                    row["relative_path"]
                    or row["filename"]
                ),
                "source_type": (
                    row["source_type"]
                    or "file"
                ),
                "rows": (
                    row["row_count"]
                    or 0
                ),
                "created_at": row[
                    "created_at"
                ],
                "metrics": metrics,
                "filepath": (
                    row["filepath"]
                    or ""
                ),
            }
        )

    return output


def aggregate_user_metrics(
    user_id,
):

    metrics = {
        "Valor Total": 0.0,
        "Receita Comercial": 0.0,
        "Custo Operacional": 0.0,
        "Volume de Produção": 0.0,
        "Ativo em Estoque": 0.0,
        "Mix de Produtos": 0.0,
        "Performance": 0.0,
        "Estratégia": 0.0,
    }

    sources = source_summary(
        user_id
    )

    for source in sources:

        source_metrics = source[
            "metrics"
        ]

        for key in metrics:

            metrics[key] += float(
                source_metrics.get(
                    key,
                    0,
                )
                or 0
            )

    return metrics


# ============================================================
# CHAT / BUSCA DE DADOS
# ============================================================

def extract_query_date(
    text,
):

    patterns = [
        r"\b(\d{1,2})[/-](\d{1,2})[/-](\d{2,4})\b",
        r"\b(\d{4})[/-](\d{1,2})[/-](\d{1,2})\b",
        r"\bdia\s+(\d{1,2})[/-](\d{1,2})(?:[/-](\d{2,4}))?\b",
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            text,
            re.I,
        )

        if not match:
            continue

        groups = match.groups()

        try:

            if (
                len(groups) == 3
                and len(groups[0]) == 4
            ):

                year, month, day = map(
                    int,
                    groups,
                )

            elif len(groups) == 3:

                day, month, year = map(
                    int,
                    groups,
                )

            else:

                day, month = map(
                    int,
                    groups[:2],
                )

                year = None

            return {
                "day": day,
                "month": month,
                "year": year,
            }

        except Exception:

            return None

    return None


def amount_for_metric(
    dataframe,
    metric_name,
):

    column = find_column(
        dataframe.columns,
        ALIASES[
            metric_name
        ],
    )

    if not column:

        return (
            0.0,
            None,
        )

    return (
        float(
            dataframe[column]
            .apply(parse_number)
            .sum()
        ),
        column,
    )


def date_mask(
    dataframe,
    wanted,
):

    column = find_date_column(
        dataframe.columns
    )

    if (
        not column
        or wanted is None
    ):

        return (
            None,
            column,
        )

    dates = parse_date_series(
        dataframe[column]
    )

    mask = (
        dates.notna()
        & (
            dates.dt.day
            == wanted["day"]
        )
        & (
            dates.dt.month
            == wanted["month"]
        )
    )

    if wanted.get(
        "year"
    ) is not None:

        year = wanted["year"]

        if year < 100:
            year += 2000

        mask &= (
            dates.dt.year
            == year
        )

    return (
        mask,
        column,
    )


def rows_matching_text(
    dataframe,
    query,
    limit=8,
):

    terms = [
        normalize(term)
        for term in re.findall(
            r"[\wÀ-ÿ]+",
            query,
        )
        if len(term) >= 3
    ]

    if not terms:
        return []

    hits = []

    for index, row in dataframe.iterrows():

        haystack = normalize(
            " ".join(
                str(value)
                for value in row.tolist()
            )
        )

        if any(
            term in haystack
            for term in terms
        ):

            values = {
                str(column): row[column]
                for column in dataframe.columns
            }

            hits.append(
                {
                    "row": int(index) + 2,
                    "values": values,
                }
            )

            if len(hits) >= limit:
                break

    return hits


def load_all_company_frames(
    user_id,
):

    frames = []

    sources = source_summary(
        user_id
    )

    for source in sources[
        :MAX_CHAT_FILES
    ]:

        filepath = source.get(
            "filepath"
        )

        if not filepath:
            continue

        path = Path(
            filepath
        )

        if (
            not path.exists()
            or not path.is_file()
        ):
            continue

        try:

            dataframe = read_dataframe(
                path
            )

            dataframe.columns = [
                str(column).strip()
                for column in dataframe.columns
            ]

            frames.append(
                {
                    "source": source,
                    "dataframe": dataframe,
                }
            )

        except Exception:

            continue

    return frames


def money(
    value,
):

    try:
        value = float(
            value
        )
    except Exception:
        value = 0.0

    sign = (
        "-"
        if value < 0
        else ""
    )

    value = abs(
        value
    )

    text = (
        f"{value:,.2f}"
        .replace(
            ",",
            "X",
        )
        .replace(
            ".",
            ",",
        )
        .replace(
            "X",
            ".",
        )
    )

    return (
        f"{sign}R$ {text}"
    )


# ============================================================
# EMOJIS PERMITIDOS
# ============================================================

ALLOWED_RESPONSE_EMOJIS = [
    "😃",
    "🥳",
    "😬",
    "📈",
    "📉",
    "📊",
    "🗂️",
    "🤖",
    "📦",
]


def apply_emoji_level(
    response,
    level,
):

    try:
        level = int(
            level or 0
        )
    except Exception:
        level = 0

    if level <= 0:
        return response

    emojis = [
        "📊",
        "🗂️",
        "🤖",
        "📈",
        "📦",
        "😃",
        "🥳",
        "😬",
        "📉",
    ]

    amount = min(
        level + 1,
        len(emojis),
    )

    return (
        response.rstrip()
        + " "
        + " ".join(
            emojis[:amount]
        )
    )


# ============================================================
# RESPOSTA INTELIGENTE DA LUCRA.AI
# ============================================================

def answer_company_question(
    user_id,
    message,
    frames=None,
):

    text = normalize(
        message
    )

    if frames is None:

        frames = load_all_company_frames(
            user_id
        )

    if not frames:

        return (
            "Não há arquivos de empresa "
            "incorporados para eu consultar. "
            "Envie um CSV/Excel ou use "
            "'Incorporar pasta'."
        )

    wanted_date = extract_query_date(
        message
    )

    asks_profit = any(
        term in text
        for term in [
            "lucro",
            "profit",
            "resultado liquido",
            "resultado líquido",
        ]
    )

    asks_revenue = any(
        term in text
        for term in [
            "venda",
            "vendas",
            "receita",
            "faturamento",
        ]
    )

    asks_cost = any(
        term in text
        for term in [
            "custo",
            "custos",
            "despesa",
            "despesas",
        ]
    )

    asks_stock = any(
        term in text
        for term in [
            "estoque",
            "armazem",
            "almoxarifado",
        ]
    )

    asks_production = any(
        term in text
        for term in [
            "producao",
            "produção",
            "produzido",
            "quantidade produzida",
        ]
    )

    asks_summary = any(
        term in text
        for term in [
            "resumo",
            "analise geral",
            "como esta",
            "visao geral",
            "visão geral",
        ]
    )

    asks_total = (
        "valor total" in text
        or bool(
            re.search(
                r"\btotal\b",
                text,
            )
        )
    )

    # --------------------------------------------------------
    # PERGUNTAS POR DATA
    # --------------------------------------------------------

    if wanted_date and (
        asks_profit
        or asks_revenue
        or asks_cost
    ):

        total_revenue = 0.0
        total_cost = 0.0

        matched_rows = 0
        date_source_count = 0

        for item in frames:

            dataframe = item[
                "dataframe"
            ]

            mask, _ = date_mask(
                dataframe,
                wanted_date,
            )

            if (
                mask is None
                or not bool(
                    mask.any()
                )
            ):
                continue

            date_source_count += 1

            subset = dataframe.loc[
                mask
            ]

            matched_rows += len(
                subset
            )

            revenue, _ = amount_for_metric(
                subset,
                "Receita Comercial",
            )

            cost, _ = amount_for_metric(
                subset,
                "Custo Operacional",
            )

            total_revenue += revenue
            total_cost += cost

        if asks_profit:

            if (
                total_revenue == 0
                and total_cost == 0
            ):

                return (
                    "Não foi possível calcular o lucro "
                    "para a data informada porque não "
                    "encontrei Receita Comercial e "
                    "Custo Operacional correspondentes "
                    "nas fontes incorporadas."
                )

            profit = (
                total_revenue
                - total_cost
            )

            date_label = (
                f"{wanted_date['day']:02d}/"
                f"{wanted_date['month']:02d}"
            )

            if wanted_date.get(
                "year"
            ):

                year = wanted_date[
                    "year"
                ]

                if year < 100:
                    year += 2000

                date_label += (
                    f"/{year:04d}"
                )

            return (
                f"Para {date_label}, considerando "
                f"as fontes encontradas, a Receita "
                f"Comercial foi {money(total_revenue)}, "
                f"o Custo Operacional foi "
                f"{money(total_cost)} e o lucro "
                f"calculado é {money(profit)}. "
                f"Foram consultadas "
                f"{date_source_count} fonte(s) e "
                f"{matched_rows} linha(s) compatível(is)."
            )

        if asks_revenue:

            if total_revenue == 0:

                return (
                    "Não encontrei Receita Comercial "
                    "correspondente à data informada "
                    "nas fontes incorporadas."
                )

            return (
                "A Receita Comercial encontrada "
                "para a data informada é "
                f"{money(total_revenue)}."
            )

        if asks_cost:

            if total_cost == 0:

                return (
                    "Não encontrei Custo Operacional "
                    "correspondente à data informada "
                    "nas fontes incorporadas."
                )

            return (
                "O Custo Operacional encontrado "
                "para a data informada é "
                f"{money(total_cost)}."
            )

    # --------------------------------------------------------
    # RESUMO GERAL
    # --------------------------------------------------------

    if asks_summary:

        metrics = aggregate_user_metrics(
            user_id
        )

        return (
            f"Resumo executivo baseado em "
            f"{len(frames)} fonte(s): "
            f"Receita Comercial "
            f"{money(metrics['Receita Comercial'])}, "
            f"Custo Operacional "
            f"{money(metrics['Custo Operacional'])}, "
            f"Estoque "
            f"{money(metrics['Ativo em Estoque'])}, "
            f"Produção "
            f"{metrics['Volume de Produção']:,.2f}, "
            f"e Valor Total "
            f"{money(metrics['Valor Total'])}."
        )

    # --------------------------------------------------------
    # LUCRO
    # --------------------------------------------------------

    if asks_profit:

        metrics = aggregate_user_metrics(
            user_id
        )

        revenue = metrics[
            "Receita Comercial"
        ]

        cost = metrics[
            "Custo Operacional"
        ]

        if (
            revenue == 0
            and cost == 0
        ):

            return (
                "Não encontrei Receita Comercial "
                "e Custo Operacional suficientes "
                "para calcular o lucro."
            )

        return (
            "Com base em todas as fontes "
            "incorporadas, a Receita Comercial "
            f"é {money(revenue)}, o Custo "
            f"Operacional é {money(cost)} e o "
            f"lucro calculado é "
            f"{money(revenue - cost)}."
        )

    # --------------------------------------------------------
    # MÉTRICAS
    # --------------------------------------------------------

    if (
        asks_revenue
        or asks_cost
        or asks_stock
        or asks_production
        or asks_total
    ):

        metrics = aggregate_user_metrics(
            user_id
        )

        if asks_revenue and not (
            asks_cost
            or asks_stock
            or asks_production
            or asks_total
        ):

            return (
                "A Receita Comercial total "
                "identificada nas fontes é "
                f"{money(metrics['Receita Comercial'])}."
            )

        if asks_cost and not (
            asks_revenue
            or asks_stock
            or asks_production
            or asks_total
        ):

            return (
                "O Custo Operacional total "
                "identificado nas fontes é "
                f"{money(metrics['Custo Operacional'])}."
            )

        if asks_stock and not (
            asks_revenue
            or asks_cost
            or asks_production
            or asks_total
        ):

            return (
                "O Ativo em Estoque total "
                "identificado nas fontes é "
                f"{money(metrics['Ativo em Estoque'])}."
            )

        if asks_production and not (
            asks_revenue
            or asks_cost
            or asks_stock
            or asks_total
        ):

            return (
                "O Volume de Produção total "
                "identificado nas fontes é "
                f"{metrics['Volume de Produção']:,.2f}."
            )

        if asks_total:

            return (
                "O Valor Total identificado "
                "nas fontes é "
                f"{money(metrics['Valor Total'])}."
            )

    # --------------------------------------------------------
    # PESQUISA TEXTUAL EM TODAS AS FONTES
    # --------------------------------------------------------

    matches = []

    for item in frames:

        hits = rows_matching_text(
            item["dataframe"],
            message,
            limit=5,
        )

        for hit in hits:

            matches.append(
                (
                    item[
                        "source"
                    ][
                        "relative_path"
                    ],
                    hit,
                )
            )

            if len(matches) >= 10:
                break

        if len(matches) >= 10:
            break

    if matches:

        lines = [
            "Encontrei correspondências "
            "nas fontes incorporadas:"
        ]

        for source_name, hit in matches:

            preview = "; ".join(
                f"{key}: {str(value)[:80]}"
                for key, value in hit[
                    "values"
                ].items()
                if (
                    str(value).strip()
                    and str(value).lower()
                    != "nan"
                )
            )

            lines.append(
                f"• {source_name} — "
                f"linha {hit['row']}: "
                f"{preview}"
            )

        return "\n".join(
            lines
        )

    return (
        "Não encontrei dados suficientes "
        "nas fontes incorporadas para "
        "responder com segurança. "
        "A LUCRA.AI não vai inventar números."
    )


# ============================================================
# CHAT HUMANO / RESUMIDO E DETALHADO
# ============================================================

MONTHS_PT = {
    1: "janeiro",
    2: "fevereiro",
    3: "março",
    4: "abril",
    5: "maio",
    6: "junho",
    7: "julho",
    8: "agosto",
    9: "setembro",
    10: "outubro",
    11: "novembro",
    12: "dezembro",
}

MONTH_LOOKUP = {
    normalize(name): number
    for number, name in MONTHS_PT.items()
}

MONTH_LOOKUP.update(
    {
        "jan": 1,
        "fev": 2,
        "abr": 4,
        "jun": 6,
        "jul": 7,
        "ago": 8,
        "nov": 11,
    }
)

CHAT_STOPWORDS = set(
    """
    a o os as um uma uns umas de do da dos das no na nos nas em por para pra pro
    com sem que qual quais quanto quanta quantos quantas quando onde como foi
    foram ser sao era eram esta estao tem tinha teve ha e ou me mim meu minha
    voce voces nos eles elas isso isto esse essa este aquele aquela total soma
    somar valor numero mes ano dia periodo armazenado armazenada armazenados
    armazenadas armazenou armazenaram armazem armazens estoque estocado estocados
    quantidade qtd qtde existe existem tenho temos lucra lupi favor diga mostre
    mostra fale fala informe sobre ate desde entre todo toda todos todas cada
    preciso quero saber gostaria poderia pode consegue ver
    """.split()
)

FINANCE_TERMS = (
    "lucro",
    "receita",
    "custo",
    "despesa",
    "venda",
    "faturamento",
    "valor",
    "dinheiro",
    "preco",
)

QUANTITY_TRIGGERS = (
    "quant",
    "qtd",
    "qtde",
    "armazen",
    "estoc",
    "palete",
    "pallet",
    "caixa",
    "unidade",
    "volume",
    "soma",
    "total de",
    "saldo",
    "peso",
)

QUANTITY_COLUMN_HINTS = (
    "quantidade",
    "qtde",
    "qtd",
    "quant",
    "paletes",
    "palete",
    "pallets",
    "pallet",
    "caixas",
    "volumes",
    "volume",
    "unidades",
    "armazenad",
    "estoque",
    "saldo",
    "peso",
    "total",
)

LOCATION_COLUMN_HINTS = (
    "armazem",
    "deposito",
    "galpao",
    "local",
    "endereco",
    "posicao",
    "setor",
    "doca",
    "rua",
    "centro",
    "filial",
    "loja",
)

PRODUCT_COLUMN_HINTS = (
    "produto",
    "descricao",
    "material",
    "mercadoria",
    "item",
    "sku",
    "artigo",
)

MONTH_COLUMN_HINTS = (
    "mes",
    "periodo",
    "competencia",
    "referencia",
)

UNIT_COLUMN_NAMES = (
    "unidade de medida",
    "unidade",
    "unid",
    "und",
    "un",
    "um",
    "embalagem",
    "tipo de volume",
)

CHAT_TOPIC_EMOJIS = [
    (("lucro", "resultado"), "💰"),
    (("receita", "venda", "faturamento"), "💵"),
    (("custo", "despesa"), "📉"),
    (("armaz", "palete", "pallet", "deposito", "galpao"), "🏬"),
    (("estoque", "estocad"), "📦"),
    (("producao", "produzid", "fabrica"), "🏭"),
    (("resumo", "visao geral", "analise geral", "como esta"), "📊"),
]

MONEY_PATTERN = re.compile(
    r"-?R\$\s?[\d\.]+,\d{2}"
)


def chat_tone_pick(
    options,
    seed,
):

    digest = hashlib.sha256(
        str(seed).encode("utf-8")
    ).digest()

    return options[
        digest[0] % len(options)
    ]


def chat_topic_emoji(message):

    text = normalize(message)

    for terms, emoji in CHAT_TOPIC_EMOJIS:

        if any(
            term in text
            for term in terms
        ):
            return emoji

    return "📊"


def smalltalk_reply(
    message,
    username,
):

    text = re.sub(
        r"[^a-z0-9 ]",
        " ",
        normalize(message),
    )

    words = text.split()

    if not words or len(words) > 7:
        return None

    joined = " ".join(words)

    if any(
        term in joined
        for term in (
            "lucro",
            "receita",
            "custo",
            "estoque",
            "venda",
            "quant",
            "armaz",
            "palete",
            "producao",
            "resumo",
            "planilha",
            "total",
            "valor",
        )
    ):
        return None

    first_name = (
        str(username or "").split() or [""]
    )[0]

    name = (
        f", {first_name}"
        if first_name
        else ""
    )

    def has(*terms):

        return any(
            re.search(
                rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])",
                joined,
            )
            for term in terms
        )

    if has(
        "obrigado",
        "obrigada",
        "valeu",
        "vlw",
        "agradeco",
        "grato",
        "grata",
        "perfeito",
    ):
        return chat_tone_pick(
            [
                f"Por nada{name}! 😊 Fico feliz em ajudar. Se precisar de mais algum número da empresa, é só perguntar. 📊",
                f"Imagina{name}! 🤝 Estou aqui para isso. Quer que eu analise mais alguma coisa?",
            ],
            message,
        )

    if has(
        "tchau",
        "ate mais",
        "ate logo",
        "falou",
        "flw",
        "bye",
    ):
        return f"Até logo{name}! 👋 Suas conversas ficam salvas aqui na LUCRA.AI."

    if has(
        "quem e voce",
        "quem e vc",
        "o que voce faz",
        "o que vc faz",
        "ajuda",
        "help",
        "como funciona",
        "o que voce sabe",
    ):
        return (
            "Eu sou a LUCRA.AI 🤖, a inteligência executiva da sua empresa.\n\n"
            "Você pode me perguntar, por exemplo:\n"
            "• \"Quantos paletes foram armazenados no A01?\" 📦\n"
            "• \"Qual foi o lucro de fevereiro?\" 💰\n"
            "• \"Faça um resumo executivo.\" 📊\n\n"
            "Nas respostas com números, você escolhe entre ⚡ Resumido ou 📋 Detalhado."
        )

    if has(
        "tudo bem",
        "como vai",
        "como voce esta",
        "tudo certo",
        "beleza",
        "blz",
    ):
        return (
            f"Tudo ótimo por aqui{name}, obrigada por perguntar! 😄 "
            "Estou pronta para analisar os dados da empresa. O que você precisa saber?"
        )

    if has("bom dia"):
        greeting = f"Bom dia{name}! ☀️"
    elif has("boa tarde"):
        greeting = f"Boa tarde{name}! 🌤️"
    elif has("boa noite"):
        greeting = f"Boa noite{name}! 🌙"
    elif has(
        "oi",
        "ola",
        "opa",
        "eai",
        "e ai",
        "hey",
        "hello",
        "salve",
    ):
        greeting = f"Olá{name}! 👋"
    else:
        return None

    return (
        f"{greeting} Sou a LUCRA.AI, sua assistente executiva. "
        "Posso consultar a planilha da empresa e responder sobre estoque, "
        "armazéns, vendas, custos e lucro. Como posso ajudar hoje? 📊"
    )


def humanize_answer(
    raw,
    message,
):

    raw = str(raw or "").strip()

    if not raw:
        return raw

    if raw.startswith("Não há arquivos"):
        return (
            "📎 Ainda não tenho nenhuma planilha da empresa para consultar.\n\n"
            "Toque em \"📎 Adicionar planilha da empresa\", logo abaixo do chat "
            "(funciona no celular e no computador), e eu passo a responder "
            "com os números reais. 😉"
        )

    if raw.startswith("Não"):
        return (
            "😬 "
            + raw
            + chat_tone_pick(
                [
                    " Se puder, me diga o período, o código (ex.: A01) ou o produto, que eu procuro de novo. 🔎",
                    " Tente informar o mês, o armazém ou o nome do produto para eu refinar a busca. 🔎",
                ],
                message,
            )
        )

    opener = chat_tone_pick(
        [
            "Pronto! ",
            "Aqui está. ",
            "Certo, analisei os dados. ",
            "Encontrei! ",
        ],
        message,
    )

    closing = chat_tone_pick(
        [
            "\n\nSe quiser, posso detalhar por período, produto ou fonte. 📊",
            "\n\nPosso cruzar esse número com outro indicador, se precisar. 📈",
            "",
        ],
        message + "#",
    )

    return (
        f"{chat_topic_emoji(message)} "
        f"{opener}{raw}{closing}"
    )


def summarize_answer(
    raw,
    message,
):

    raw = str(raw or "").strip()

    text = normalize(message)

    if not raw or raw.startswith("Não"):
        return "Sem dados suficientes."

    if raw.startswith("Encontrei correspondências"):

        count = sum(
            1
            for line in raw.splitlines()
            if line.startswith("•")
        )

        return f"{count} registro(s) encontrado(s)."

    values = MONEY_PATTERN.findall(raw)

    if values:

        if (
            raw.startswith("Resumo executivo")
            and len(values) >= 3
        ):
            return (
                f"Receita {values[0]} • "
                f"Custo {values[1]} • "
                f"Estoque {values[2]}."
            )

        if (
            "lucro" in text
            or "lucro calculado" in raw
        ):
            return values[-1] + "."

        return values[0] + "."

    numbers = re.findall(
        r"\d[\d\.,]*",
        raw,
    )

    if numbers:
        return numbers[-1].rstrip(".,") + "."

    return raw.split(".")[0] + "."


def pick_column(
    columns,
    hints,
    exclude=(),
):

    candidates = [
        (column, normalize(column))
        for column in columns
        if column not in exclude
    ]

    for hint in hints:

        for column, name in candidates:

            if re.search(
                rf"(?<![a-z0-9]){re.escape(hint)}",
                name,
            ):
                return column

    return None


def pick_unit_column(
    columns,
    exclude=(),
):

    for column in columns:

        if column in exclude:
            continue

        name = normalize(column)

        if (
            name in UNIT_COLUMN_NAMES
            or name.startswith("unidade de")
        ):
            return column

    return None


def numeric_ratio(series):

    values = [
        value
        for value in series.tolist()[:500]
        if str(value).strip()
        and str(value).strip().lower() != "nan"
    ]

    if not values:
        return 0.0

    good = 0

    for value in values:

        if isinstance(
            value,
            (int, float),
        ) and not isinstance(
            value,
            bool,
        ):
            good += 1
            continue

        cleaned = str(value).strip().replace(
            "R$",
            "",
        )

        if re.fullmatch(
            r"[\s\-\+\(]*[\d\.,]+[\s\)]*%?",
            cleaned,
        ):
            good += 1

    return good / len(values)


def value_matches_month(
    value,
    month,
):

    text = normalize(value)

    if not text or text == "nan":
        return False

    name = normalize(MONTHS_PT[month])

    if name in text or re.search(
        rf"(?<![a-z]){name[:3]}(?![a-z])",
        text,
    ):
        return True

    numbers = re.findall(
        r"\d+",
        text,
    )

    if not numbers:
        return False

    if len(numbers[0]) <= 2 and len(numbers) == 1:
        return int(numbers[0]) == month

    if len(numbers) >= 2 and len(numbers[0]) == 4:
        return int(numbers[1]) == month

    if len(numbers) >= 2 and len(numbers[0]) <= 2:
        if len(numbers) >= 3 or len(numbers[1]) == 4:
            target = (
                numbers[1]
                if len(numbers) >= 3
                else numbers[0]
            )
            return int(target) == month

    return False


def token_pattern(token):

    return re.compile(
        rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])"
    )


def format_quantity(value):

    value = float(value)

    if value.is_integer():

        number = int(round(value))

        if abs(number) < 10000:
            return str(number)

        return f"{number:,}".replace(
            ",",
            ".",
        )

    return (
        f"{value:,.2f}"
        .replace(",", "X")
        .replace(".", ",")
        .replace("X", ".")
    )


def clean_label(value):

    text = str(value).strip()

    if text.endswith(".0") and text[:-2].isdigit():
        text = text[:-2]

    if text.isupper() and len(text) > 3 and " " in text:
        return text.lower()

    return text


def answer_quantity_question(
    frames,
    message,
):

    text = normalize(message)

    if not any(
        trigger in text
        for trigger in QUANTITY_TRIGGERS
    ):
        return None

    codes = []
    words = []
    month = None
    year = None

    for raw in re.findall(
        r"[0-9A-Za-zÀ-ÿ]+",
        message,
    ):

        token = normalize(raw)

        if not token:
            continue

        if re.fullmatch(
            r"(19|20)\d{2}",
            token,
        ):
            year = int(token)
            continue

        if token in MONTH_LOOKUP and month is None:
            month = MONTH_LOOKUP[token]
            continue

        if re.search(r"\d", token) and re.search(r"[a-z]", token):
            codes.append(token)
            continue

        if token.isdigit():
            continue

        if len(token) >= 3 and token not in CHAT_STOPWORDS:
            words.append(token)

    if not codes and not words and month is None:
        return None

    if not codes and any(
        term in text
        for term in FINANCE_TERMS
    ):
        return None

    used = []

    for item in frames:

        dataframe = item["dataframe"]

        if dataframe is None or dataframe.empty:
            continue

        dataframe = dataframe.copy()

        dataframe.columns = [
            str(column)
            for column in dataframe.columns
        ]

        columns = list(dataframe.columns)

        row_text = dataframe.astype(str).apply(
            lambda row: " " + normalize(" ".join(row.tolist())) + " ",
            axis=1,
        )

        mask = pd.Series(
            True,
            index=dataframe.index,
        )

        active = False
        missing_code = False

        for code in codes:

            pattern = token_pattern(code)

            hit = row_text.map(
                lambda value, pattern=pattern: bool(pattern.search(value))
            )

            if not hit.any():
                missing_code = True
                break

            mask &= hit
            active = True

        if missing_code:
            continue

        for word in words:

            pattern = token_pattern(word)

            hit = row_text.map(
                lambda value, pattern=pattern: bool(pattern.search(value))
            )

            if hit.any():
                mask &= hit
                active = True

        location_column = pick_column(
            columns,
            LOCATION_COLUMN_HINTS,
        )

        product_column = pick_column(
            columns,
            PRODUCT_COLUMN_HINTS,
            exclude=(location_column,),
        )

        month_column = pick_column(
            columns,
            MONTH_COLUMN_HINTS,
            exclude=(location_column, product_column),
        )

        date_column = find_date_column(columns)

        unit_column = pick_unit_column(
            columns,
            exclude=(location_column, product_column, month_column),
        )

        if month is not None:

            month_hit = None

            if month_column:

                month_hit = dataframe[month_column].map(
                    lambda value: value_matches_month(value, month)
                )

            elif date_column:

                parsed = parse_date_series(
                    dataframe[date_column]
                )

                month_hit = parsed.dt.month == month

                if year:
                    month_hit &= parsed.dt.year == year

            else:

                pattern = token_pattern(
                    normalize(MONTHS_PT[month])
                )

                candidate = row_text.map(
                    lambda value: bool(pattern.search(value))
                )

                if candidate.any():
                    month_hit = candidate

            if month_hit is not None:

                mask &= month_hit.fillna(False).astype(bool)
                active = True

        if not active:
            continue

        subset = dataframe.loc[
            mask.fillna(False).astype(bool)
        ]

        if subset.empty:
            continue

        excluded = {
            column
            for column in (
                location_column,
                product_column,
                month_column,
                date_column,
                unit_column,
            )
            if column
        }

        quantity_column = None

        for hint in QUANTITY_COLUMN_HINTS:

            for column in columns:

                if column in excluded:
                    continue

                if (
                    hint in normalize(column)
                    and numeric_ratio(dataframe[column]) >= 0.6
                ):
                    quantity_column = column
                    break

            if quantity_column:
                break

        if quantity_column:
            values = [
                parse_number(value)
                for value in subset[quantity_column].tolist()
            ]
        else:
            values = [1.0] * len(subset)

        used.append(
            {
                "source": item["source"].get(
                    "relative_path",
                    "planilha",
                ),
                "subset": subset,
                "values": values,
                "quantity": quantity_column,
                "location": location_column,
                "product": product_column,
                "month": month_column,
                "date": date_column,
                "unit": unit_column,
            }
        )

    if not used:

        if codes:
            labels = ", ".join(
                code.upper()
                for code in codes
            )
            return {
                "summary": "Não encontrado.",
                "detailed": (
                    f"😬 Não encontrei registros de {labels} nas planilhas da empresa. "
                    "Confira se o código está escrito igual ao da planilha. 🔎"
                ),
                "modes": True,
                "found": False,
            }

        return None

    total = sum(
        sum(entry["values"])
        for entry in used
    )

    matched_rows = sum(
        len(entry["subset"])
        for entry in used
    )

    def uniques(key):

        found = []

        for entry in used:

            column = entry[key]

            if not column:
                continue

            for value in entry["subset"][column].tolist():

                label = clean_label(value)

                if (
                    label
                    and label.lower() != "nan"
                    and label not in found
                ):
                    found.append(label)

        return found

    locations = uniques("location")
    products = uniques("product")
    units = uniques("unit")

    month_label = ""

    if month is not None:

        month_label = MONTHS_PT[month]

        if year:
            month_label += f" de {year}"

    else:

        month_values = uniques("month")

        if len(month_values) == 1:

            for number, name in MONTHS_PT.items():

                if value_matches_month(month_values[0], number):
                    month_label = name
                    break

    quantity_column = next(
        (
            entry["quantity"]
            for entry in used
            if entry["quantity"]
        ),
        None,
    )

    quantity_name = normalize(
        quantity_column or ""
    )

    unit_word = ""

    if not quantity_column:
        unit_word = "registro(s)"
    elif len(units) == 1:
        unit_word = units[0].lower()
    else:
        for hint, word in (
            ("palete", "paletes"),
            ("pallet", "paletes"),
            ("caixa", "caixas"),
            ("unidade", "unidades"),
            ("volume", "volumes"),
            ("peso", "kg"),
        ):
            if hint in quantity_name:
                unit_word = word
                break

    if not unit_word:
        if "palete" in text or "pallet" in text:
            unit_word = "paletes"
        elif "caixa" in text:
            unit_word = "caixas"
        else:
            unit_word = "unidades"

    plural = total != 1

    if "armaz" in quantity_name or "armaz" in text:
        verb = "foram armazenados" if plural else "foi armazenado"
        emoji = "🏬"
    elif (
        "estoq" in quantity_name
        or "estoq" in text
        or "saldo" in quantity_name
    ):
        verb = "há em estoque"
        emoji = "📦"
    else:
        verb = "foram registrados" if plural else "foi registrado"
        emoji = "📦"

    parts = []

    location_column = next(
        (
            entry["location"]
            for entry in used
            if entry["location"]
        ),
        None,
    )

    if len(locations) == 1 and location_column:

        label = normalize(location_column)

        noun = (
            "armazém"
            if "armaz" in label
            else str(location_column).strip().lower()
        )

        preposition = (
            "Na"
            if label.startswith(
                (
                    "rua",
                    "posicao",
                    "doca",
                    "filial",
                    "loja",
                    "unidade",
                    "localizacao",
                )
            )
            else "No"
        )

        parts.append(
            f"{preposition} {noun} {locations[0]}"
        )

    elif codes:

        parts.append(
            "Em "
            + ", ".join(
                code.upper()
                for code in codes
            )
        )

    if month_label:
        parts.append(
            f"no mês de {month_label}"
        )

    number = format_quantity(total)

    product_part = (
        f" de {products[0]}"
        if len(products) == 1
        else ""
    )

    if parts:
        sentence = (
            f"{', '.join(parts)}, {verb} "
            f"{number} {unit_word}{product_part}."
        )
    else:
        sentence = (
            f"{verb[:1].upper()}{verb[1:]} "
            f"{number} {unit_word}{product_part}."
        )

    breakdown_key = (
        "product"
        if len(products) > 1
        else (
            "location"
            if len(locations) > 1
            else None
        )
    )

    lines = []

    if breakdown_key:

        sums = {}

        for entry in used:

            column = entry[breakdown_key]

            if not column:
                continue

            for label, amount in zip(
                entry["subset"][column].tolist(),
                entry["values"],
            ):
                key = clean_label(label)
                sums[key] = sums.get(key, 0.0) + amount

        for key, amount in sorted(
            sums.items(),
            key=lambda pair: -pair[1],
        )[:8]:
            lines.append(
                f"• {key}: {format_quantity(amount)}"
            )

    sources = []

    for entry in used:

        if entry["source"] not in sources:
            sources.append(entry["source"])

    detailed = f"{emoji} {sentence}"

    if lines:
        detailed += "\n\nDetalhamento:\n" + "\n".join(lines)

    detailed += (
        f"\n\n📄 Fonte: {', '.join(sources[:3])} — "
        f"{matched_rows} linha(s) analisada(s)."
    )

    return {
        "summary": f"{number}.",
        "detailed": detailed,
        "modes": True,
        "found": True,
    }


def build_chat_answer(
    user,
    message,
):

    small = smalltalk_reply(
        message,
        user["username"],
    )

    if small:
        return {
            "summary": small,
            "detailed": small,
            "modes": False,
        }

    frames = load_all_company_frames(
        user["id"]
    )

    pinned = [
        item
        for item in frames
        if item["source"].get("source_type") == "empresa"
    ]

    others = [
        item
        for item in frames
        if item["source"].get("source_type") != "empresa"
    ]

    not_found = None

    for group in (
        pinned,
        others,
    ):

        if not group:
            continue

        result = answer_quantity_question(
            group,
            message,
        )

        if not result:
            continue

        if result.get("found", True):
            return result

        not_found = not_found or result

    if not_found:
        return not_found

    raw = answer_company_question(
        user["id"],
        message,
        frames=pinned + others,
    )

    detailed = humanize_answer(
        raw,
        message,
    )

    if not frames or str(raw).startswith("Não"):
        return {
            "summary": detailed,
            "detailed": detailed,
            "modes": False,
        }

    return {
        "summary": summarize_answer(
            raw,
            message,
        ),
        "detailed": detailed,
        "modes": True,
    }


def conversation_title(message):

    clean = " ".join(
        str(message or "").split()
    )

    if len(clean) > 60:
        return clean[:60].rstrip() + "…"

    return clean or "Nova conversa"


# ============================================================
# FIM DA PARTE 1
# ============================================================
# NÃO COLE NADA AQUI.
# MANDE "2" PARA RECEBER A CONTINUAÇÃO EXATA.
# ============================================================
# LUCRA.AI — EXECUTIVE VISION
# MAIN.PY — PARTE 2 DE 2
# CONTINUAÇÃO EXATA DA PARTE 1
# ============================================================


# ============================================================
# HTML / CSS / JAVASCRIPT
# ============================================================

PAGE_STYLE = r"""
<style>
:root{
    --gold:#D4AF37;
    --gold2:#FFF4A3;
    --black:#050505;
    --white:#FFFFFF;
    --bg:#F5F5F5;
    --line:#DEDEDE;
    --text:#111111;
    --muted:#6B6B6B;
    --danger:#A31919;
    --shadow:0 18px 50px rgba(0,0,0,.08);
}

*{
    box-sizing:border-box;
}

html,
body{
    margin:0;
    padding:0;
    min-height:100%;
    font-family:Inter,Arial,Helvetica,sans-serif;
    background:var(--bg);
    color:var(--text);
}

body{
    min-height:100vh;
}

button,
input,
select,
textarea{
    font:inherit;
}

button{
    cursor:pointer;
}

a{
    color:inherit;
    text-decoration:none;
}

img{
    max-width:100%;
}

.container{
    width:min(1200px,calc(100% - 32px));
    margin:0 auto;
}

.topbar{
    position:sticky;
    top:0;
    z-index:100;
    min-height:70px;
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:18px;
    padding:12px 24px;
    background:rgba(5,5,5,.97);
    color:#fff;
    border-bottom:1px solid rgba(212,175,55,.55);
    backdrop-filter:blur(16px);
}

.brand{
    display:flex;
    align-items:center;
    gap:10px;
    font-size:20px;
    font-weight:900;
    letter-spacing:.05em;
}

.brand-logo{
    width:38px;
    height:38px;
    border-radius:50%;
    object-fit:cover;
    border:1px solid rgba(212,175,55,.65);
    background:#111;
}

.brand span{
    color:var(--gold);
}

.top-actions{
    display:flex;
    align-items:center;
    gap:9px;
    flex-wrap:wrap;
}

.top-actions a,
.top-button{
    border:1px solid rgba(255,255,255,.25);
    border-radius:10px;
    padding:9px 12px;
    color:#fff;
    background:transparent;
}

.top-actions a:hover,
.top-button:hover{
    border-color:var(--gold);
    color:var(--gold);
}

.shell{
    width:min(1200px,calc(100% - 32px));
    margin:28px auto 70px;
}

.hero{
    position:relative;
    overflow:hidden;
    background:#fff;
    border:1px solid var(--line);
    border-radius:24px;
    padding:28px;
    box-shadow:var(--shadow);
    margin-bottom:20px;
}

.hero::after{
    content:"";
    position:absolute;
    width:230px;
    height:230px;
    border-radius:50%;
    border:15px solid rgba(212,175,55,.12);
    right:-90px;
    top:-100px;
}

.eyebrow{
    color:#80640c;
    font-size:11px;
    font-weight:900;
    letter-spacing:.15em;
    text-transform:uppercase;
}

h1{
    margin:8px 0;
    font-size:clamp(29px,5vw,54px);
    line-height:1.02;
}

h2{
    margin:0 0 8px;
}

h3{
    margin:0 0 8px;
}

.muted{
    color:var(--muted);
}

.grid{
    display:grid;
    gap:18px;
}

.two-columns{
    display:grid;
    grid-template-columns:1.25fr .75fr;
    gap:18px;
}

.metric-grid{
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:14px;
    margin:18px 0;
}

.metric-card{
    min-height:125px;
    background:#fff;
    border:1px solid var(--line);
    border-radius:17px;
    padding:18px;
    box-shadow:0 10px 30px rgba(0,0,0,.045);
}

.metric-card span{
    display:block;
    color:var(--muted);
    font-size:11px;
    font-weight:800;
    letter-spacing:.08em;
    text-transform:uppercase;
}

.metric-card strong{
    display:block;
    margin-top:10px;
    font-size:25px;
}

.metric-card.featured{
    color:#fff;
    background:#050505;
    border-color:#050505;
}

.metric-card.featured span{
    color:#cfcfcf;
}

.panel{
    background:#fff;
    border:1px solid var(--line);
    border-radius:20px;
    padding:22px;
    box-shadow:0 12px 32px rgba(0,0,0,.045);
}

.panel + .panel{
    margin-top:18px;
}

.input{
    width:100%;
    border:1px solid #cfcfcf;
    background:#fff;
    color:#111;
    border-radius:12px;
    padding:12px 14px;
    outline:none;
}

.input:focus{
    border-color:var(--gold);
    box-shadow:0 0 0 3px rgba(212,175,55,.14);
}

textarea.input{
    min-height:100px;
    resize:vertical;
}

.primary-btn,
.gold-btn{
    border:0;
    border-radius:12px;
    padding:11px 16px;
    background:var(--gold);
    color:#050505;
    font-weight:900;
}

.primary-btn:hover,
.gold-btn:hover{
    filter:brightness(.95);
}

.black-btn{
    border:0;
    border-radius:12px;
    padding:11px 16px;
    background:#050505;
    color:#fff;
    font-weight:900;
}

.secondary-btn{
    border:1px solid #cfcfcf;
    border-radius:12px;
    padding:11px 16px;
    background:#fff;
    color:#111;
    font-weight:800;
}

.danger-btn{
    border:1px solid #b72a2a;
    border-radius:10px;
    padding:9px 12px;
    background:#fff;
    color:#a31919;
    font-weight:800;
}

.row{
    display:flex;
    align-items:center;
    gap:10px;
    flex-wrap:wrap;
}

.space{
    justify-content:space-between;
}

.form-group{
    margin-bottom:13px;
}

.form-group label{
    display:block;
    margin-bottom:6px;
    font-size:12px;
    font-weight:800;
}

.notice{
    border-radius:12px;
    padding:12px 14px;
    margin-bottom:14px;
    background:#f0f0f0;
    border:1px solid #ddd;
    font-size:13px;
}

.notice.error{
    background:#fff1f1;
    color:#8f1010;
    border-color:#e4a5a5;
}

.notice.gold{
    background:#fffbe1;
    color:#5e4c00;
    border-color:#ead27b;
}

.status{
    display:inline-flex;
    align-items:center;
    justify-content:center;
    padding:7px 10px;
    border-radius:999px;
    font-size:10px;
    font-weight:900;
    letter-spacing:.04em;
}

.status.pending{
    background:#fff4a3;
    color:#514300;
}

.status.approved{
    background:#ededed;
    color:#222;
}

.status.admin{
    background:#050505;
    color:#fff;
}

.table-wrap{
    width:100%;
    overflow-x:auto;
}

table{
    width:100%;
    border-collapse:collapse;
}

th,
td{
    padding:12px 10px;
    border-bottom:1px solid #ececec;
    text-align:left;
    font-size:13px;
    vertical-align:middle;
}

th{
    font-size:11px;
    text-transform:uppercase;
    letter-spacing:.07em;
    color:#666;
}

.empty{
    padding:28px 10px;
    text-align:center;
    color:#777;
}

@property --lucra-angle{
    syntax:'<angle>';
    inherits:false;
    initial-value:0deg;
}

body.auth-page{
    min-height:100vh;
    min-height:100dvh;
    display:flex;
    flex-direction:column;
    justify-content:center;
    align-items:center;
    padding:28px 16px;
    position:relative;
    overflow-x:hidden;
    overflow-y:auto;
    color:#FFFFFF;
    background:
        radial-gradient(
            circle at 50% 0%,
            rgba(212,175,55,.20),
            transparent 30%
        ),
        radial-gradient(
            circle at 50% 100%,
            rgba(255,244,163,.07),
            transparent 42%
        ),
        linear-gradient(
            145deg,
            #050505 0%,
            #0B0B0B 50%,
            #050505 100%
        );
    background-attachment:fixed;
}

.auth-dataflow{
    position:fixed;
    inset:0;
    width:100%;
    height:100%;
    z-index:0;
    pointer-events:none;
}

.auth-grid{
    position:fixed;
    inset:-80px;
    z-index:0;
    pointer-events:none;
    background-image:
        linear-gradient(
            rgba(212,175,55,.055) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(212,175,55,.055) 1px,
            transparent 1px
        );
    background-size:56px 56px;
    -webkit-mask-image:radial-gradient(circle at 50% 45%, #000 0%, transparent 72%);
    mask-image:radial-gradient(circle at 50% 45%, #000 0%, transparent 72%);
    animation:authGridMove 9s linear infinite;
}

@keyframes authGridMove{
    from{
        transform:translate3d(0,0,0);
    }
    to{
        transform:translate3d(56px,56px,0);
    }
}

.auth-lupi-stage{
    position:fixed;
    left:50%;
    top:50%;
    width:min(1180px,150vw);
    aspect-ratio:2/1;
    transform:translate(-50%,-50%);
    z-index:1;
    pointer-events:none;
}

.auth-lupi-stage svg{
    position:absolute;
    inset:0;
    width:100%;
    height:100%;
    overflow:visible;
}

.lupi-track{
    fill:none;
    stroke:rgba(212,175,55,.16);
    stroke-width:2;
}

.lupi-flow{
    fill:none;
    stroke:url(#lupiGold);
    stroke-width:3;
    stroke-linecap:round;
    stroke-dasharray:140 860;
    filter:url(#lupiGlow);
    animation:lupiFlow 7s linear infinite;
}

.lupi-flow-2{
    stroke-width:2;
    stroke-dasharray:60 440;
    opacity:.75;
    animation-duration:11s;
    animation-direction:reverse;
}

@keyframes lupiFlow{
    from{
        stroke-dashoffset:0;
    }
    to{
        stroke-dashoffset:-1000;
    }
}

.lupi-head{
    fill:#FFF4A3;
    filter:url(#lupiGlow);
}

.lupi-head-2{
    fill:#D4AF37;
}

.lupi-code{
    fill:rgba(255,244,163,.42);
    font-family:"Courier New",Consolas,monospace;
    font-size:15px;
    letter-spacing:3px;
}

.lupi-ring{
    position:absolute;
    left:50%;
    top:50%;
    border-radius:50%;
    transform:translate(-50%,-50%);
    border:1px dashed rgba(212,175,55,.22);
    animation:lupiRing 38s linear infinite;
}

.lupi-ring.r1{
    width:min(560px,118vw);
    height:min(560px,118vw);
}

.lupi-ring.r2{
    width:min(700px,140vw);
    height:min(700px,140vw);
    border-style:solid;
    border-color:transparent;
    border-top-color:rgba(255,244,163,.35);
    border-bottom-color:rgba(212,175,55,.22);
    animation-duration:16s;
    animation-direction:reverse;
}

.lupi-ring.r3{
    width:min(840px,165vw);
    height:min(840px,165vw);
    border-color:rgba(212,175,55,.08);
    animation-duration:60s;
}

@keyframes lupiRing{
    from{
        transform:translate(-50%,-50%) rotate(0deg);
    }
    to{
        transform:translate(-50%,-50%) rotate(360deg);
    }
}

.auth-wrap{
    position:relative;
    z-index:2;
    width:min(450px,100%);
    display:flex;
    flex-direction:column;
    align-items:center;
    gap:20px;
}

.lucra-logo{
    position:relative;
    width:min(360px,100%);
    padding:24px 18px 18px;
    display:flex;
    flex-direction:column;
    align-items:center;
    justify-content:center;
    text-align:center;
    isolation:isolate;
}

.lucra-logo-orbit{
    position:absolute;
    inset:0;
    border-radius:50%;
    border:1px solid rgba(212,175,55,.18);
    z-index:-1;
}

.lucra-logo-orbit::before{
    content:"";
    position:absolute;
    inset:-2px;
    border-radius:50%;
    padding:2px;
    background:conic-gradient(
        from var(--lucra-angle),
        transparent 0deg,
        transparent 230deg,
        rgba(212,175,55,.25) 290deg,
        #FFF4A3 345deg,
        #FFFFFF 360deg
    );
    -webkit-mask:
        linear-gradient(#000 0 0) content-box,
        linear-gradient(#000 0 0);
    -webkit-mask-composite:xor;
    mask-composite:exclude;
    filter:drop-shadow(0 0 8px rgba(255,244,163,.85));
    animation:lucraAngle 2.6s linear infinite;
}

.lucra-logo-orbit::after{
    content:"";
    position:absolute;
    inset:-14px -10px;
    border-radius:50%;
    border:1px solid transparent;
    border-left-color:rgba(255,244,163,.45);
    border-right-color:rgba(212,175,55,.30);
    animation:lupiSpin 5.5s linear infinite reverse;
}

@keyframes lucraAngle{
    to{
        --lucra-angle:360deg;
    }
}

@keyframes lupiSpin{
    from{
        transform:rotate(0deg);
    }
    to{
        transform:rotate(360deg);
    }
}

.lucra-logo-bolts{
    position:absolute;
    inset:-6px -18px;
    width:calc(100% + 36px);
    height:calc(100% + 12px);
    z-index:-1;
    overflow:visible;
}

.lucra-bolt{
    fill:none;
    stroke:#FFF4A3;
    stroke-width:2.2;
    stroke-linecap:round;
    stroke-linejoin:round;
    stroke-dasharray:240;
    stroke-dashoffset:240;
    filter:url(#boltGlow);
    animation:lucraBolt 3.2s linear infinite;
}

.lucra-bolt.b2{
    animation-delay:.8s;
}

.lucra-bolt.b3{
    animation-delay:1.6s;
    stroke:#D4AF37;
}

.lucra-bolt.b4{
    animation-delay:2.4s;
}

@keyframes lucraBolt{
    0%{
        stroke-dashoffset:240;
        opacity:0;
    }
    6%{
        opacity:1;
    }
    18%{
        stroke-dashoffset:0;
        opacity:1;
    }
    22%{
        opacity:.2;
    }
    25%{
        opacity:1;
    }
    34%{
        stroke-dashoffset:-240;
        opacity:0;
    }
    100%{
        stroke-dashoffset:-240;
        opacity:0;
    }
}

.lucra-logo-word{
    position:relative;
    margin:0;
    font-size:clamp(40px,12vw,64px);
    line-height:1;
    font-weight:950;
    letter-spacing:.08em;
    white-space:nowrap;
    background:linear-gradient(
        100deg,
        #D4AF37 0%,
        #FFF4A3 22%,
        #FFFFFF 32%,
        #FFF4A3 42%,
        #D4AF37 60%,
        #FFF4A3 80%,
        #D4AF37 100%
    );
    background-size:220% 100%;
    -webkit-background-clip:text;
    background-clip:text;
    color:transparent;
    -webkit-text-fill-color:transparent;
    filter:drop-shadow(0 0 14px rgba(212,175,55,.55));
    animation:
        lucraShine 4.5s linear infinite,
        lucraCharge 6s ease-in-out infinite;
}

@keyframes lucraShine{
    from{
        background-position:0% 50%;
    }
    to{
        background-position:-220% 50%;
    }
}

@keyframes lucraCharge{
    0%,
    100%{
        filter:drop-shadow(0 0 12px rgba(212,175,55,.45));
    }
    46%{
        filter:drop-shadow(0 0 14px rgba(212,175,55,.55));
    }
    48%{
        filter:drop-shadow(0 0 30px rgba(255,244,163,.95));
    }
    50%{
        filter:drop-shadow(0 0 10px rgba(212,175,55,.40));
    }
    52%{
        filter:drop-shadow(0 0 26px rgba(255,244,163,.85));
    }
}

.lucra-logo-sub{
    margin-top:10px;
    font-size:11px;
    font-weight:800;
    letter-spacing:.42em;
    color:rgba(255,244,163,.82);
}

.lucra-particles{
    position:absolute;
    left:50%;
    top:50%;
    width:0;
    height:0;
    z-index:-1;
}

.lucra-particles i{
    position:absolute;
    left:0;
    top:0;
    width:4px;
    height:4px;
    margin:-2px;
    border-radius:50%;
    background:#FFF4A3;
    box-shadow:0 0 10px #D4AF37, 0 0 18px rgba(255,244,163,.65);
    transform:rotate(calc(var(--i) * 25.7deg)) translateX(var(--r,150px));
    animation:lucraParticle calc(5s + var(--i) * .35s) linear infinite;
    animation-delay:calc(var(--i) * -.6s);
    opacity:.85;
}

.lucra-particles i:nth-child(odd){
    --r:118px;
    width:3px;
    height:3px;
    background:#D4AF37;
}

.lucra-particles i:nth-child(3n){
    --r:175px;
}

@keyframes lucraParticle{
    from{
        transform:rotate(calc(var(--i) * 25.7deg)) translateX(var(--r,150px)) scale(1);
    }
    50%{
        opacity:.25;
    }
    to{
        transform:rotate(calc(var(--i) * 25.7deg + 360deg)) translateX(var(--r,150px)) scale(1);
    }
}

.auth-card{
    position:relative;
    z-index:2;
    width:100%;
    padding:24px 24px 22px;
    border-radius:25px;
    color:#FFFFFF;
    background:
        linear-gradient(
            160deg,
            rgba(26,22,10,.78) 0%,
            rgba(8,8,8,.82) 55%,
            rgba(5,5,5,.88) 100%
        );
    -webkit-backdrop-filter:blur(16px) saturate(140%);
    backdrop-filter:blur(16px) saturate(140%);
    border:1px solid rgba(212,175,55,.60);
    box-shadow:
        0 35px 100px rgba(0,0,0,.65),
        0 0 36px rgba(212,175,55,.22),
        inset 0 1px 0 rgba(255,244,163,.18);
    overflow:hidden;
}

.auth-card::before{
    content:"";
    position:absolute;
    inset:0;
    border-radius:inherit;
    pointer-events:none;
    background:linear-gradient(
        125deg,
        rgba(255,255,255,.10) 0%,
        rgba(255,255,255,.03) 28%,
        transparent 45%
    );
}

.auth-card::after{
    content:"";
    position:absolute;
    inset:0;
    border-radius:inherit;
    padding:1px;
    pointer-events:none;
    background:conic-gradient(
        from var(--lucra-angle),
        transparent 0deg,
        transparent 280deg,
        #FFF4A3 340deg,
        #D4AF37 360deg
    );
    -webkit-mask:
        linear-gradient(#000 0 0) content-box,
        linear-gradient(#000 0 0);
    -webkit-mask-composite:xor;
    mask-composite:exclude;
    animation:lucraAngle 6s linear infinite;
}

.auth-card > *{
    position:relative;
    z-index:1;
}

.auth-card-head{
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:12px;
    margin-bottom:16px;
}

.auth-title{
    margin:0;
    font-size:22px;
    font-weight:900;
    letter-spacing:.06em;
    color:#FFFFFF;
}

.auth-subtitle{
    margin:4px 0 0;
    color:rgba(255,244,163,.78);
    font-size:12px;
    letter-spacing:.08em;
}

.lupi-shell{
    display:inline-flex;
    align-items:center;
    gap:9px;
    margin-top:8px;
}

.lupi-orbit{
    position:relative;
    width:42px;
    height:42px;
    flex:0 0 42px;
    display:grid;
    place-items:center;
    border-radius:50%;
    border:1px solid rgba(212,175,55,.42);
    box-shadow:0 0 24px rgba(212,175,55,.24);
    background:rgba(5,5,5,.6);
    overflow:hidden;
}

.lupi-orbit:before,
.lupi-orbit:after{
    content:'';
    position:absolute;
    inset:5px;
    border:2px solid transparent;
    border-top-color:#D4AF37;
    border-bottom-color:rgba(255,255,255,.65);
    border-radius:50%;
    animation:lupiSpin 2.6s linear infinite;
}

.lupi-orbit:after{
    inset:10px;
    border-left-color:#FFF4A3;
    border-right-color:transparent;
    animation-duration:1.8s;
    animation-direction:reverse;
}

.lupi-core{
    position:relative;
    z-index:2;
    font-weight:950;
    color:#D4AF37;
    font-size:12px;
    text-shadow:0 0 8px rgba(255,244,163,.7);
}

.lupi-label{
    font-size:11px;
    font-weight:800;
    letter-spacing:.12em;
    color:#FFF4A3;
    line-height:1.25;
}

.lupi-label small{
    display:block;
    font-size:10px;
    font-weight:600;
    letter-spacing:.06em;
    color:rgba(255,255,255,.6);
}

.auth-card .lupi-shell{
    margin-top:0;
}

.auth-switch{
    display:flex;
    gap:6px;
    padding:5px;
    margin-bottom:18px;
    border-radius:13px;
    background:rgba(0,0,0,.45);
    border:1px solid rgba(212,175,55,.28);
}

.auth-switch button{
    flex:1;
    border:0;
    padding:10px;
    border-radius:9px;
    background:transparent;
    color:rgba(255,255,255,.72);
    font-weight:700;
    cursor:pointer;
}

.auth-switch button.active{
    background:linear-gradient(135deg,rgba(212,175,55,.28),rgba(255,244,163,.14));
    color:#FFF4A3;
    font-weight:900;
    box-shadow:0 0 16px rgba(212,175,55,.25), inset 0 0 0 1px rgba(212,175,55,.55);
}

.auth-card .form-group label{
    color:#FFF4A3;
    letter-spacing:.04em;
}

.auth-card .input{
    background:rgba(0,0,0,.58);
    border:1px solid rgba(212,175,55,.50);
    color:#FFFFFF;
    padding:13px 14px;
    font-size:15px;
}

.auth-card .input::placeholder{
    color:rgba(255,255,255,.55);
}

.auth-card .input:focus{
    border-color:#FFF4A3;
    background:rgba(0,0,0,.72);
    box-shadow:0 0 0 3px rgba(212,175,55,.22), 0 0 18px rgba(212,175,55,.30);
}

.auth-card .input:-webkit-autofill,
.auth-card .input:-webkit-autofill:hover,
.auth-card .input:-webkit-autofill:focus{
    -webkit-text-fill-color:#FFFFFF;
    caret-color:#FFFFFF;
    -webkit-box-shadow:0 0 0 1000px #0d0c08 inset;
    box-shadow:0 0 0 1000px #0d0c08 inset;
    transition:background-color 9999s ease-in-out 0s;
}

.auth-card .code-input{
    text-align:center;
    font-size:26px;
    font-weight:900;
    letter-spacing:.5em;
    padding-left:calc(14px + .5em);
}

.auth-card .black-btn,
.auth-card .primary-btn{
    width:100%;
    padding:13px 16px;
    border:1px solid rgba(255,244,163,.65);
    border-radius:13px;
    background:linear-gradient(135deg,#D4AF37 0%,#FFF4A3 50%,#D4AF37 100%);
    background-size:200% 100%;
    color:#050505;
    font-weight:950;
    letter-spacing:.14em;
    cursor:pointer;
    box-shadow:0 0 22px rgba(212,175,55,.42);
    transition:background-position .4s ease, box-shadow .25s ease, transform .15s ease;
}

.auth-card .black-btn:hover,
.auth-card .primary-btn:hover{
    background-position:100% 0;
    box-shadow:0 0 32px rgba(255,244,163,.60);
}

.auth-card .black-btn:active,
.auth-card .primary-btn:active{
    transform:translateY(1px);
}

.auth-card .black-btn:disabled{
    opacity:.6;
    cursor:wait;
}

.auth-links{
    display:flex;
    justify-content:space-between;
    align-items:center;
    flex-wrap:wrap;
    gap:8px;
    margin-top:14px;
}

.auth-card .chip{
    border:1px solid rgba(212,175,55,.45);
    border-radius:999px;
    padding:8px 13px;
    background:rgba(0,0,0,.40);
    color:#FFF4A3;
    font-size:12px;
    font-weight:800;
    letter-spacing:.04em;
    cursor:pointer;
}

.auth-card .chip:hover{
    border-color:#FFF4A3;
    box-shadow:0 0 14px rgba(212,175,55,.35);
}

.auth-message{
    display:none;
    margin:12px 0 0;
    padding:11px 13px;
    border-radius:12px;
    font-size:13px;
    line-height:1.45;
    background:rgba(212,175,55,.10);
    border:1px solid rgba(212,175,55,.40);
    color:#FFF4A3;
}

.auth-message.show{
    display:block;
}

.auth-message.error{
    background:rgba(163,25,25,.22);
    border-color:rgba(255,120,120,.55);
    color:#FFD6D6;
}

.auth-message.success{
    background:rgba(212,175,55,.16);
    border-color:rgba(255,244,163,.65);
    color:#FFF4A3;
}

.auth-card .notice{
    background:rgba(255,255,255,.06);
    border-color:rgba(255,255,255,.18);
    color:#FFFFFF;
}

.auth-card .notice.error{
    background:rgba(163,25,25,.22);
    border-color:rgba(255,120,120,.55);
    color:#FFD6D6;
}

.auth-card .notice.gold{
    background:rgba(212,175,55,.14);
    border-color:rgba(212,175,55,.55);
    color:#FFF4A3;
}

.forgot-head{
    margin-bottom:14px;
}

.forgot-head h2{
    margin:0 0 6px;
    font-size:18px;
    letter-spacing:.06em;
    color:#FFF4A3;
}

.forgot-head p{
    margin:0;
    font-size:13px;
    line-height:1.5;
    color:rgba(255,255,255,.75);
}

.forgot-steps{
    display:flex;
    gap:6px;
    margin-bottom:16px;
}

.forgot-steps span{
    flex:1;
    height:4px;
    border-radius:4px;
    background:rgba(255,255,255,.14);
    transition:background .3s ease, box-shadow .3s ease;
}

.forgot-steps span.done{
    background:linear-gradient(90deg,#D4AF37,#FFF4A3);
    box-shadow:0 0 10px rgba(212,175,55,.55);
}

.auth-footer{
    margin-top:18px;
    text-align:center;
    font-size:12px;
    line-height:1.5;
    color:rgba(255,255,255,.58);
}

.auth-footer a{
    color:#FFF4A3;
    font-weight:800;
}

[hidden]{
    display:none !important;
}

@media(max-width:480px){

    body.auth-page{
        justify-content:flex-start;
        padding:18px 12px 26px;
    }

    .auth-wrap{
        gap:14px;
    }

    .lucra-logo{
        padding:20px 10px 14px;
    }

    .lucra-particles i{
        --r:120px;
    }

    .lucra-particles i:nth-child(odd){
        --r:96px;
    }

    .lucra-particles i:nth-child(3n){
        --r:138px;
    }

    .auth-card{
        padding:20px 16px 18px;
        border-radius:21px;
    }

    .auth-card-head{
        flex-direction:column;
        align-items:flex-start;
    }
}

@media(max-height:640px) and (min-width:481px){

    body.auth-page{
        justify-content:flex-start;
    }
}

@media(prefers-reduced-motion:reduce){

    .auth-grid,
    .lucra-particles i,
    .lupi-ring{
        animation-duration:120s;
    }

    .lucra-logo-word{
        animation:lucraShine 12s linear infinite;
    }
}

.dashboard-layout{
    display:grid;
    grid-template-columns:240px 1fr;
    min-height:calc(100vh - 70px);
}

.sidebar{
    position:sticky;
    top:70px;
    height:calc(100vh - 70px);
    padding:18px 12px;
    background:#050505;
    color:#fff;
    border-right:1px solid rgba(212,175,55,.35);
}

.sidebar-logo{
    display:flex;
    align-items:center;
    gap:9px;
    padding:8px 10px 18px;
    font-weight:900;
}

.sidebar-logo img{
    width:35px;
    height:35px;
    border-radius:50%;
    object-fit:cover;
}

.sidebar-menu{
    display:grid;
    gap:7px;
}

.sidebar-menu button,
.sidebar-menu a{
    width:100%;
    border:1px solid transparent;
    background:transparent;
    color:#ddd;
    text-align:left;
    padding:11px 12px;
    border-radius:11px;
}

.sidebar-menu button:hover,
.sidebar-menu a:hover,
.sidebar-menu .active{
    color:#fff;
    background:rgba(212,175,55,.12);
    border-color:rgba(212,175,55,.3);
}

.dashboard-main{
    min-width:0;
    padding:24px;
}

.chat-box{
    display:flex;
    flex-direction:column;
    height:650px;
    overflow:hidden;
    border:1px solid #dedede;
    border-radius:20px;
    background:#fff;
}

.chat-header{
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:10px;
    padding:14px 16px;
    border-bottom:1px solid #e5e5e5;
}

.chat-title{
    display:flex;
    align-items:center;
    gap:10px;
    font-weight:900;
}

.chat-icon{
    width:38px;
    height:38px;
    display:grid;
    place-items:center;
    border-radius:50%;
    color:#050505;
    background:var(--gold);
    font-size:18px;
    box-shadow:0 0 20px rgba(212,175,55,.2);
}

.chat-messages{
    flex:1;
    min-height:0;
    overflow-y:auto;
    padding:18px;
    background:#fafafa;
}

.message{
    max-width:82%;
    padding:12px 14px;
    margin-bottom:12px;
    border-radius:16px;
    white-space:pre-wrap;
    line-height:1.45;
    font-size:14px;
}

.message.ai{
    margin-right:auto;
    background:#fff;
    border:1px solid #e0e0e0;
}

.message.user{
    margin-left:auto;
    background:#050505;
    color:#fff;
    border-bottom-right-radius:5px;
}

.chat-tools{
    display:flex;
    gap:7px;
    padding:9px 12px;
    overflow-x:auto;
    border-top:1px solid #eee;
    background:#fff;
}

.quick-btn{
    white-space:nowrap;
    border:1px solid #d6d6d6;
    border-radius:999px;
    padding:7px 10px;
    background:#fff;
    font-size:11px;
}

.quick-btn:hover{
    border-color:var(--gold);
}

.chat-input-area{
    display:flex;
    align-items:flex-end;
    gap:8px;
    padding:12px;
    border-top:1px solid #e2e2e2;
    background:#fff;
}

.chat-input{
    flex:1;
    min-height:45px;
    max-height:130px;
    resize:none;
    border:1px solid #cfcfcf;
    border-radius:13px;
    padding:12px;
    outline:none;
}

.chat-input:focus{
    border-color:var(--gold);
}

.attach-btn,
.send-btn{
    width:45px;
    height:45px;
    border-radius:12px;
    border:1px solid #d2d2d2;
    background:#fff;
    font-weight:900;
}

.send-btn{
    border:0;
    background:var(--gold);
    color:#050505;
}

.source-list{
    display:grid;
    gap:9px;
}

.source-item{
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:10px;
    padding:11px;
    border:1px solid #e2e2e2;
    border-radius:12px;
}

.source-item small{
    display:block;
    color:#777;
    margin-top:3px;
}

.upload-box{
    border:1.5px dashed #c7c7c7;
    border-radius:16px;
    padding:18px;
    background:#fcfcfc;
}

.upload-box:hover{
    border-color:var(--gold);
}

.progress{
    width:100%;
    height:7px;
    margin-top:10px;
    overflow:hidden;
    border-radius:999px;
    background:#e9e9e9;
}

.progress span{
    display:block;
    width:0;
    height:100%;
    background:var(--gold);
    transition:width .25s ease;
}

.gravity-title{
    display:flex;
    flex-wrap:wrap;
    gap:2px;
    margin:0;
    cursor:pointer;
    user-select:none;
}

.gravity-letter{
    display:inline-block;
    transition:
        transform .65s cubic-bezier(.2,.8,.2,1),
        opacity .65s ease;
}

.gravity-title.falling .gravity-letter{
    transform:
        translateY(
            calc(
                90px
                + var(--fall,0px)
            )
        )
        rotate(
            var(--rotate,0deg)
        );
    opacity:.15;
}

.gravity-title.rebuilding .gravity-letter{
    animation:rebuildLetter .75s ease forwards;
}

@keyframes rebuildLetter{
    0%{
        transform:
            translateY(90px)
            rotate(30deg);
        opacity:.1;
    }
    100%{
        transform:
            translateY(0)
            rotate(0);
        opacity:1;
    }
}

.click-spark{
    position:fixed;
    width:7px;
    height:7px;
    border-radius:50%;
    pointer-events:none;
    z-index:999999;
    background:var(--gold);
    box-shadow:
        0 0 8px var(--gold),
        0 0 18px rgba(212,175,55,.6);
    animation:spark .65s ease-out forwards;
}

@keyframes spark{
    0%{
        transform:translate(0,0) scale(1);
        opacity:1;
    }
    100%{
        transform:
            translate(
                var(--sx),
                var(--sy)
            )
            scale(.1);
        opacity:0;
    }
}

.loop-number{
    position:relative;
    display:inline-flex;
    align-items:center;
    justify-content:center;
    min-width:74px;
    height:74px;
    margin:6px;
    border-radius:50%;
    border:1px solid rgba(212,175,55,.45);
    background:#050505;
    color:#fff;
    overflow:hidden;
}

.loop-number span{
    position:relative;
    z-index:2;
    font-size:21px;
    font-weight:900;
}

.loop-number::after{
    content:"";
    position:absolute;
    width:150%;
    height:150%;
    border:3px solid var(--gold);
    border-radius:44%;
    animation:numberLoop 2.8s linear infinite;
}

@keyframes numberLoop{
    0%{
        transform:rotate(0deg) scale(.8);
    }
    50%{
        transform:rotate(180deg) scale(1.1);
    }
    100%{
        transform:rotate(360deg) scale(.8);
    }
}

.loading-dots{
    display:inline-flex;
    gap:4px;
    align-items:center;
}

.loading-dots span{
    width:6px;
    height:6px;
    border-radius:50%;
    background:var(--gold);
    animation:loadingDot 1s infinite alternate;
}

.loading-dots span:nth-child(2){
    animation-delay:.15s;
}

.loading-dots span:nth-child(3){
    animation-delay:.3s;
}

@keyframes loadingDot{
    from{
        opacity:.25;
        transform:translateY(0);
    }
    to{
        opacity:1;
        transform:translateY(-4px);
    }
}

.toast{
    position:fixed;
    z-index:99999;
    right:18px;
    bottom:18px;
    max-width:min(400px,calc(100% - 36px));
    padding:13px 15px;
    border-radius:13px;
    color:#fff;
    background:#050505;
    border:1px solid rgba(212,175,55,.5);
    box-shadow:0 15px 50px rgba(0,0,0,.3);
    opacity:0;
    transform:translateY(15px);
    pointer-events:none;
    transition:.25s;
}

.toast.show{
    opacity:1;
    transform:translateY(0);
}

.mobile-only{
    display:none;
}

@media(max-width:1000px){

    .metric-grid{
        grid-template-columns:repeat(2,1fr);
    }

    .two-columns{
        grid-template-columns:1fr;
    }

    .dashboard-layout{
        display:block;
    }

    .sidebar{
        position:static;
        height:auto;
    }

    .sidebar-menu{
        grid-template-columns:repeat(3,1fr);
    }
}

@media(max-width:700px){

    .topbar{
        padding:10px 14px;
    }

    .top-actions{
        display:none;
    }

    .container,
    .shell{
        width:min(100% - 20px,1200px);
    }

    .dashboard-main{
        padding:14px 10px;
    }

    .metric-grid{
        grid-template-columns:1fr 1fr;
        gap:9px;
    }

    .metric-card{
        min-height:105px;
        padding:13px;
    }

    .metric-card strong{
        font-size:18px;
    }

    .sidebar-menu{
        grid-template-columns:1fr 1fr;
    }

    .chat-box{
        height:calc(100vh - 170px);
        min-height:520px;
    }

    .message{
        max-width:92%;
    }

    .auth-card{
        padding:22px;
    }

    .mobile-only{
        display:block;
    }
}

@media(max-width:430px){

    .metric-grid{
        grid-template-columns:1fr;
    }

    .sidebar-menu{
        grid-template-columns:1fr;
    }

    .hero,
    .panel{
        padding:17px;
        border-radius:17px;
    }

    h1{
        font-size:34px;
    }
}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border:0;}
body{-webkit-user-select:none;user-select:none;}
input,textarea,.message,td,[contenteditable]{-webkit-user-select:text;user-select:text;}
img{-webkit-user-drag:none;}
.ai-panel{padding:0!important;overflow:hidden;background:#0b0b0b!important;border-color:#1d1d1d!important;}
.ai-shell{display:grid;grid-template-columns:260px 1fr;height:680px;background:#0b0b0b;color:#f2f2f2;position:relative;}
.ai-history{border-right:1px solid #1f1f1f;background:#080808;display:flex;flex-direction:column;min-height:0;}
.ai-history-head{padding:16px;display:grid;gap:10px;border-bottom:1px solid #1a1a1a;}
.ai-history-head strong{color:#fff;font-size:14px;letter-spacing:.04em;}
.ai-new-btn{border:1px solid rgba(212,175,55,.5);background:#111;color:#FFF4A3;border-radius:12px;padding:10px;font-weight:800;cursor:pointer;}
.ai-new-btn:hover{background:#1a1608;}
.ai-history-list{flex:1;overflow-y:auto;padding:10px;display:grid;align-content:start;gap:6px;}
.ai-history-empty{color:#666;font-size:13px;padding:10px;}
.ai-history-item{display:flex;align-items:center;gap:6px;border-radius:12px;padding:4px;border:1px solid transparent;}
.ai-history-item.active{background:#161616;border-color:rgba(212,175,55,.35);}
.ai-history-open{flex:1;min-width:0;text-align:left;background:none;border:0;color:#ddd;padding:8px;cursor:pointer;}
.ai-history-open span{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:13px;}
.ai-history-open small{color:#777;font-size:11px;}
.ai-chat{display:flex;flex-direction:column;min-width:0;min-height:0;}
.ai-chat-head{display:flex;align-items:center;gap:12px;padding:16px 20px;border-bottom:1px solid #1a1a1a;}
.ai-chat-title{flex:1;min-width:0;}
.ai-chat-title strong{display:block;color:#fff;font-size:17px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.ai-chat-title small{color:#8a8a8a;font-size:12px;}
.ai-history-toggle{display:none;width:40px;height:40px;border-radius:12px;border:1px solid #2a2a2a;background:#151515;color:#eee;font-size:18px;cursor:pointer;place-items:center;}
.ai-emoji-btn{border:1px solid #2a2a2a;background:#151515;color:#eee;border-radius:999px;padding:8px 12px;font-size:12px;cursor:pointer;}
.ai-messages{flex:1;min-height:0;overflow-y:auto;padding:22px 20px;background:#0b0b0b;}
.ai-row{display:flex;flex-direction:column;align-items:flex-start;margin-bottom:18px;}
.ai-row.user{align-items:flex-end;}
.ai-tag{display:inline-block;font-size:11px;letter-spacing:.12em;font-weight:800;color:#bdbdbd;background:#1d1d1d;border-radius:7px;padding:6px 10px;margin-bottom:10px;}
.ai-row .message{max-width:86%;margin:0;font-size:15px;line-height:1.6;white-space:pre-wrap;border:0;box-shadow:none;}
.ai-row .message.ai{background:transparent;color:#f1f1f1;padding:0 2px;}
.ai-row .message.user{background:#262626;color:#f5f5f5;border-radius:18px;padding:13px 18px;}
.ai-row .message.ai.ai-awaiting{color:#bdbdbd;}
.ai-word{animation:aiWordIn .45s ease both;}
@keyframes aiWordIn{from{opacity:0;filter:blur(6px);}to{opacity:1;filter:blur(0);}}
.ai-typing{display:flex;gap:6px;padding:6px 2px!important;}
.ai-typing span{width:8px;height:8px;border-radius:50%;background:#D4AF37;animation:aiDot 1s infinite ease-in-out;}
.ai-typing span:nth-child(2){animation-delay:.15s;}
.ai-typing span:nth-child(3){animation-delay:.3s;}
@keyframes aiDot{0%,100%{opacity:.25;transform:translateY(0);}50%{opacity:1;transform:translateY(-4px);}}
.ai-modes{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap;}
.ai-mode-btn{border:1px solid #2c2c2c;background:#141414;color:#e8e8e8;border-radius:999px;padding:8px 14px;font-size:13px;font-weight:700;cursor:pointer;}
.ai-mode-btn.active{background:linear-gradient(135deg,#D4AF37,#FFF4A3);color:#050505;border-color:transparent;}
.ai-quick{display:flex;gap:8px;overflow-x:auto;padding:8px 20px 0;}
.ai-quick .quick-btn{background:#141414;border-color:#262626;color:#d8d8d8;}
.ai-sheet{padding:10px 20px 0;}
.ai-sheet-pinned{display:flex;align-items:center;gap:10px;background:#121212;border:1px solid rgba(212,175,55,.35);border-radius:14px;padding:10px 12px;color:#eee;}
.ai-sheet-pinned div{flex:1;min-width:0;}
.ai-sheet-pinned strong{display:block;color:#FFF4A3;font-size:13px;}
.ai-sheet-pinned small{display:block;color:#8a8a8a;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.ai-sheet-add{width:100%;border:1.5px dashed rgba(212,175,55,.5);background:#0f0f0f;color:#FFF4A3;border-radius:14px;padding:11px;font-weight:700;cursor:pointer;}
.ai-trash,.admin-trash{border:1px solid #2a2a2a;background:#161616;border-radius:10px;width:38px;height:38px;cursor:pointer;font-size:16px;flex:none;}
.ai-trash:hover,.admin-trash:hover{border-color:#e05353;background:#2a1212;}
.ai-composer{margin:12px 20px 18px;background:#161616;border:1px solid #262626;border-radius:20px;padding:12px 14px;}
.ai-input{width:100%;background:transparent;border:0;outline:none;color:#f2f2f2;font-size:15px;resize:none;min-height:28px;max-height:140px;font-family:inherit;}
.ai-input::placeholder{color:#7a7a7a;}
.ai-composer-row{display:flex;justify-content:space-between;align-items:center;margin-top:8px;}
.ai-plus{width:40px;height:40px;border-radius:12px;background:#222;border:0;color:#ddd;font-size:22px;cursor:pointer;}
.ai-send{width:44px;height:44px;border-radius:13px;border:0;background:#fff;color:#050505;font-size:20px;font-weight:900;cursor:pointer;}
.ai-send:disabled{opacity:.5;}
.kicked-overlay{position:fixed;inset:0;z-index:9999;display:grid;place-items:center;background:rgba(0,0,0,.85);backdrop-filter:blur(6px);padding:20px;}
.kicked-card{max-width:420px;text-align:center;background:#0b0b0b;border:1px solid rgba(212,175,55,.45);border-radius:22px;padding:30px;color:#fff;box-shadow:0 0 60px rgba(212,175,55,.18);}
.kicked-card h2{color:#FFF4A3;margin:10px 0;}
.kicked-card p{color:#bbb;}
.kicked-icon{font-size:42px;}
.chefe-stage{position:relative;height:300px;margin:12px 0;border-radius:24px;background:#050505;overflow:hidden;cursor:pointer;border:1px solid rgba(212,175,55,.3);box-shadow:inset 0 0 80px rgba(212,175,55,.08);}
.chefe-stage canvas{width:100%;height:100%;display:block;}
.chefe-hint{position:absolute;bottom:12px;left:0;right:0;text-align:center;color:#8a7a3a;font-size:12px;letter-spacing:.2em;pointer-events:none;}
.admin-tabs{display:flex;gap:8px;background:#0b0b0b;padding:6px;border-radius:16px;width:fit-content;max-width:100%;margin-bottom:16px;flex-wrap:wrap;}
.admin-tab{border:0;background:transparent;color:#bbb;padding:11px 18px;border-radius:12px;font-weight:800;cursor:pointer;display:flex;gap:8px;align-items:center;}
.admin-tab.active{background:linear-gradient(135deg,#D4AF37,#FFF4A3);color:#050505;}
.admin-tab .count{background:rgba(127,127,127,.25);border-radius:999px;padding:2px 8px;font-size:12px;}
.admin-pane{display:none;}
.admin-pane.active{display:block;}
.admin-user-list{display:grid;gap:10px;margin-top:10px;}
.admin-user{display:flex;align-items:center;gap:12px;padding:14px;border:1px solid #e5e5e5;border-radius:16px;background:#fff;}
.admin-avatar{width:42px;height:42px;border-radius:50%;display:grid;place-items:center;background:#050505;color:#FFF4A3;font-weight:900;flex:none;}
.admin-user-info{flex:1;min-width:0;}
.admin-user-info strong{display:block;}
.admin-user-info small{display:block;color:#777;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.admin-user-actions{display:flex;gap:8px;flex-wrap:wrap;}
@media(max-width:900px){
    .ai-shell{grid-template-columns:1fr;height:calc(100vh - 140px);min-height:560px;}
    .ai-history{position:absolute;top:0;bottom:0;left:0;width:min(82%,300px);z-index:5;transform:translateX(-105%);transition:transform .25s ease;box-shadow:20px 0 40px rgba(0,0,0,.6);}
    .ai-shell.history-open .ai-history{transform:none;}
    .ai-history-toggle{display:grid;}
    .ai-row .message{max-width:94%;}
    .chefe-stage{height:230px;}
    .admin-user{flex-wrap:wrap;}
}
</style>
"""


# ============================================================
# JAVASCRIPT GLOBAL
# ============================================================

GLOBAL_SCRIPT = r"""
<script>

function getCsrfToken(){
    const element = document.querySelector(
        'meta[name="csrf-token"]'
    );

    return element
        ? element.getAttribute("content")
        : "";
}


async function apiFetch(
    url,
    options = {}
){
    options.headers = options.headers || {};

    const csrf = getCsrfToken();

    if(csrf){
        options.headers["X-CSRF-Token"] = csrf;
    }

    if(
        options.body &&
        !(options.body instanceof FormData)
    ){
        options.headers["Content-Type"] =
            "application/json";
    }

    const response = await fetch(
        url,
        options
    );

    const text = await response.text();

    let data;

    try{
        data = JSON.parse(text);
    }catch{
        data = {
            ok:false,
            error:text || "Resposta inválida."
        };
    }

    if(!response.ok){
        throw new Error(
            data.error ||
            "Ocorreu um erro."
        );
    }

    return data;
}


function toast(
    message
){
    let element =
        document.getElementById(
            "lucra-toast"
        );

    if(!element){
        element = document.createElement(
            "div"
        );

        element.id =
            "lucra-toast";

        element.className =
            "toast";

        document.body.appendChild(
            element
        );
    }

    element.textContent =
        message;

    element.classList.add(
        "show"
    );

    clearTimeout(
        window.__lucraToastTimer
    );

    window.__lucraToastTimer =
        setTimeout(
            () => {
                element.classList.remove(
                    "show"
                );
            },
            3200
        );
}


function createSpark(
    x,
    y
){
    for(
        let i = 0;
        i < 8;
        i++
    ){

        const spark =
            document.createElement(
                "span"
            );

        spark.className =
            "click-spark";

        const angle =
            (
                Math.PI * 2 * i
            ) / 8;

        const distance =
            20 + Math.random() * 28;

        spark.style.left =
            `${x}px`;

        spark.style.top =
            `${y}px`;

        spark.style.setProperty(
            "--sx",
            `${Math.cos(angle) * distance}px`
        );

        spark.style.setProperty(
            "--sy",
            `${Math.sin(angle) * distance}px`
        );

        document.body.appendChild(
            spark
        );

        setTimeout(
            () => spark.remove(),
            700
        );
    }
}


document.addEventListener(
    "click",
    event => {

        if(
            event.target.closest(
                "button,a,input,textarea,select"
            )
        ){

            createSpark(
                event.clientX,
                event.clientY
            );

        }

    },
    true
);


document.addEventListener(
    "touchstart",
    event => {

        const touch =
            event.touches[0];

        if(touch){

            createSpark(
                touch.clientX,
                touch.clientY
            );

        }

    },
    {
        passive:true
    }
);


function setupGravityTitle(){

    const title =
        document.querySelector(
            ".gravity-title"
        );

    if(!title){
        return;
    }

    title.innerHTML =
        "";

    const text =
        "BEM VINDO CHEFE";

    [...text].forEach(
        (letter,index) => {

            const span =
                document.createElement(
                    "span"
                );

            span.className =
                "gravity-letter";

            span.textContent =
                letter === " "
                    ? "\u00A0"
                    : letter;

            span.style.setProperty(
                "--fall",
                `${Math.random() * 70}px`
            );

            span.style.setProperty(
                "--rotate",
                `${(Math.random() - .5) * 55}deg`
            );

            title.appendChild(
                span
            );

        }
    );

    title.addEventListener(
        "click",
        () => {

            title.classList.remove(
                "rebuilding"
            );

            title.classList.add(
                "falling"
            );

            setTimeout(
                () => {

                    title.classList.remove(
                        "falling"
                    );

                    title.classList.add(
                        "rebuilding"
                    );

                    setTimeout(
                        () => {
                            title.classList.remove(
                                "rebuilding"
                            );
                        },
                        800
                    );

                },
                3000
            );

        }
    );
}


document.addEventListener(
    "DOMContentLoaded",
    setupGravityTitle
);

function showKicked(message){
    if(document.getElementById("kickedOverlay")){ return; }
    const overlay = document.createElement("div");
    overlay.id = "kickedOverlay";
    overlay.className = "kicked-overlay";
    const card = document.createElement("div");
    card.className = "kicked-card";
    const icon = document.createElement("div");
    icon.className = "kicked-icon";
    icon.textContent = "⚠️";
    const title = document.createElement("h2");
    title.textContent = message || "Você foi desconectado da LUCRA IA!";
    const text = document.createElement("p");
    text.textContent = "Seu acesso foi removido pelo administrador. Para entrar novamente, o administrador precisa aceitar seu login.";
    const link = document.createElement("a");
    link.className = "gold-btn";
    link.href = "/login?kicked=1";
    link.textContent = "Ir para o login";
    card.append(icon, title, text, link);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
    setTimeout(() => { location.href = "/login?kicked=1"; }, 7000);
}
(function(){
    document.addEventListener("contextmenu", event => {
        if(!event.target.closest("input,textarea")){ event.preventDefault(); }
    });
    document.addEventListener("keydown", event => {
        const key = (event.key || "").toLowerCase();
        const mod = event.ctrlKey || event.metaKey;
        if(event.key === "F12" || (mod && event.shiftKey && ["i","j","c","k"].includes(key)) || (mod && ["u","s"].includes(key))){
            event.preventDefault();
            event.stopPropagation();
            toast("🔒 Ação bloqueada pela proteção da LUCRA.AI.");
        }
    }, true);
    document.addEventListener("dragstart", event => {
        if(event.target.tagName === "IMG"){ event.preventDefault(); }
    });
    if(document.body && document.body.dataset.session === "user"){
        setInterval(async () => {
            try{
                const response = await fetch("/api/session-status", {cache:"no-store"});
                if(response.status === 401){
                    const data = await response.json().catch(() => ({}));
                    if(data.kicked){ showKicked(data.error); }
                    else { location.href = "/login"; }
                }
            }catch(error){}
        }, 15000);
    }
})();
</script>
"""


# ============================================================
# LOGIN
# ============================================================

LOGIN_HTML = r"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0, viewport-fit=cover"
>

<meta
    name="csrf-token"
    content="{{ csrf_token() }}"
>

<meta
    name="theme-color"
    content="#050505"
>

<link
    rel="manifest"
    href="/manifest.json"
>

<title>LUCRA.AI — Login</title>

{{ style|safe }}

</head>

<body class="auth-page">

<canvas
    id="lucraDataFlow"
    class="auth-dataflow"
    aria-hidden="true"
></canvas>

<div
    class="auth-grid"
    aria-hidden="true"
></div>

<div style="text-align:center; z-index:10; position:relative;">
<img src="/static/images/logo.png" style="width:170px; border-radius:15px; margin-bottom:10px;">
<h1 style="color:#FFD700; letter-spacing:8px; font-weight:900; margin:0;">LUCRA.IA</h1>
</div>


<div
    class="auth-lupi-stage"
    aria-hidden="true"
>

    <div class="lupi-ring r1"></div>
    <div class="lupi-ring r2"></div>
    <div class="lupi-ring r3"></div>

    <svg
        viewBox="0 0 1000 500"
        preserveAspectRatio="xMidYMid meet"
    >

        <defs>

            <linearGradient
                id="lupiGold"
                x1="0"
                y1="0"
                x2="1"
                y2="0"
            >
                <stop offset="0" stop-color="#D4AF37" stop-opacity=".15"/>
                <stop offset=".5" stop-color="#FFF4A3"/>
                <stop offset="1" stop-color="#D4AF37" stop-opacity=".15"/>
            </linearGradient>

            <filter
                id="lupiGlow"
                x="-50%"
                y="-50%"
                width="200%"
                height="200%"
            >
                <feGaussianBlur stdDeviation="5" result="blur"/>
                <feMerge>
                    <feMergeNode in="blur"/>
                    <feMergeNode in="SourceGraphic"/>
                </feMerge>
            </filter>

            <path
                id="lupiPath"
                pathLength="1000"
                d="M500,250 C600,95 880,95 880,250 C880,405 600,405 500,250 C400,95 120,95 120,250 C120,405 400,405 500,250 Z"
            />

        </defs>

        <use href="#lupiPath" class="lupi-track"/>
        <use href="#lupiPath" class="lupi-flow"/>
        <use href="#lupiPath" class="lupi-flow lupi-flow-2"/>

        <text class="lupi-code">
            <textPath href="#lupiPath" startOffset="0%">
                R$ 4.218.903 ▲ 12,8% · 0x7F3A · MIX 38% · 101101 · EBITDA 22,4% · 0xD4AF37 · ESTOQUE 1.284 · 0110 · R$ 982.110 ▼ 3,1% · IA 360°
                <animate
                    attributeName="startOffset"
                    from="0%"
                    to="-50%"
                    dur="26s"
                    repeatCount="indefinite"
                />
            </textPath>
        </text>

        <circle r="7" class="lupi-head">
            <animateMotion dur="7s" repeatCount="indefinite">
                <mpath href="#lupiPath"/>
            </animateMotion>
        </circle>

        <circle r="4" class="lupi-head lupi-head-2">
            <animateMotion dur="7s" begin="-3.5s" repeatCount="indefinite">
                <mpath href="#lupiPath"/>
            </animateMotion>
        </circle>

    </svg>

</div>


<main class="auth-wrap">

    <div
        class="lucra-logo"
        role="img"
        aria-label="LUCRA.AI"
    >

        <div class="lucra-logo-orbit"></div>

        <svg
            class="lucra-logo-bolts"
            viewBox="0 0 400 160"
            preserveAspectRatio="none"
            aria-hidden="true"
        >
            <defs>
                <filter
                    id="boltGlow"
                    x="-50%"
                    y="-50%"
                    width="200%"
                    height="200%"
                >
                    <feGaussianBlur stdDeviation="2.4" result="blur"/>
                    <feMerge>
                        <feMergeNode in="blur"/>
                        <feMergeNode in="blur"/>
                        <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                </filter>
            </defs>

            <polyline class="lucra-bolt b1" points="200,4 228,10 240,4 270,16 286,10 318,26 336,22 360,44 372,42"/>
            <polyline class="lucra-bolt b2" points="396,80 380,96 388,104 366,120 372,128 340,142 330,140 300,154"/>
            <polyline class="lucra-bolt b3" points="200,156 172,150 160,156 130,144 114,150 82,134 64,138 40,116 28,118"/>
            <polyline class="lucra-bolt b4" points="4,80 20,64 12,56 34,40 28,32 60,18 70,20 100,6"/>
        </svg>

        <div class="lucra-particles" aria-hidden="true">
            {% for i in range(14) %}
                <i style="--i:{{ i }}"></i>
            {% endfor %}
        </div>

        <div class="lucra-logo-word">
            LUCRA.AI
        </div>

        <div class="lucra-logo-sub">
            EXECUTIVE VISION
        </div>

    </div>


    <div class="auth-card">

        <div class="auth-card-head">

            <div>
                <h1 class="auth-title">
                    ACESSO SEGURO
                </h1>

                <p class="auth-subtitle">
                    Plataforma de inteligência executiva
                </p>
            </div>

            <div class="lupi-shell">
                <div class="lupi-orbit">
                    <span class="lupi-core">AI</span>
                </div>
                <span class="lupi-label">
                    LUPI
                    <small>Inteligência ativa</small>
                </span>
            </div>

        </div>

        {% if error %}
            <div class="notice error">
                {{ error }}
            </div>
        {% endif %}

        {% if kicked %}
            <div class="notice error">
                ⚠️ Você foi desconectado da LUCRA IA!
                Para entrar novamente, o administrador precisa aceitar seu login.
            </div>
        {% endif %}

        {% if pending %}
            <div class="notice gold">
                Sua conta foi criada e está aguardando
                aprovação do administrador.
            </div>
        {% endif %}

        <div
            class="auth-switch"
            id="authSwitch"
        >

            <button
                type="button"
                id="loginTab"
                class="active"
                onclick="showLogin()"
            >
                Entrar
            </button>

            <button
                type="button"
                id="registerTab"
                onclick="showRegister()"
            >
                Criar conta
            </button>

        </div>


        <section id="loginView">

            <form
                id="loginForm"
                method="POST"
                action="/login"
                novalidate
            >

                <input
                    type="hidden"
                    name="csrf_token"
                    value="{{ csrf_token() }}"
                >

                <div class="form-group">

                    <label for="loginIdentifier">
                        E-mail ou telefone
                    </label>

                    <input
                        id="loginIdentifier"
                        class="input"
                        name="identifier"
                        placeholder="E-mail ou telefone"
                        autocomplete="username"
                        maxlength="160"
                        required
                    >

                </div>


                <div class="form-group">

                    <label for="loginPassword">
                        Senha
                    </label>

                    <input
                        id="loginPassword"
                        class="input"
                        type="password"
                        name="password"
                        placeholder="Senha"
                        autocomplete="current-password"
                        maxlength="120"
                        required
                    >

                </div>


                <button
                    id="loginButton"
                    class="black-btn"
                    type="submit"
                >
                    ENTRAR
                </button>

            </form>

            <div class="auth-links">

                <button
                    id="forgotButton"
                    class="chip"
                    type="button"
                >
                    Esqueci minha senha
                </button>

                <button
                    class="chip"
                    type="button"
                    onclick="showRegister()"
                >
                    Criar conta
                </button>

            </div>

        </section>


        <section
            id="forgotView"
            hidden
        >

            <div class="forgot-head">

                <h2>
                    RECUPERAR SENHA
                </h2>

                <p id="forgotDescription">
                    Informe o e-mail ou telefone cadastrado.
                    O código de verificação será enviado
                    somente para o contato registrado na sua conta.
                </p>

            </div>

            <div
                class="forgot-steps"
                aria-hidden="true"
            >
                <span id="forgotStep1" class="done"></span>
                <span id="forgotStep2"></span>
                <span id="forgotStep3"></span>
            </div>


            <form
                id="forgotRequestForm"
                novalidate
            >

                <div class="form-group">

                    <label for="forgotIdentifier">
                        E-mail ou telefone cadastrado
                    </label>

                    <input
                        id="forgotIdentifier"
                        class="input"
                        placeholder="E-mail ou telefone"
                        autocomplete="username"
                        maxlength="160"
                        required
                    >

                </div>

                <button
                    class="black-btn"
                    type="submit"
                >
                    ENVIAR CÓDIGO
                </button>

            </form>


            <form
                id="forgotCodeForm"
                novalidate
                hidden
            >

                <div class="form-group">

                    <label for="forgotCode">
                        Código de verificação
                    </label>

                    <input
                        id="forgotCode"
                        class="input code-input"
                        inputmode="numeric"
                        pattern="[0-9]*"
                        autocomplete="one-time-code"
                        maxlength="6"
                        placeholder="000000"
                        required
                    >

                </div>

                <button
                    class="black-btn"
                    type="submit"
                >
                    VALIDAR CÓDIGO
                </button>

                <div class="auth-links">
                    <button
                        id="forgotResend"
                        class="chip"
                        type="button"
                    >
                        Reenviar código
                    </button>
                </div>

            </form>


            <form
                id="forgotPasswordForm"
                novalidate
                hidden
            >

                <div class="form-group">

                    <label for="newPassword">
                        Nova senha
                    </label>

                    <input
                        id="newPassword"
                        class="input"
                        type="password"
                        minlength="6"
                        maxlength="120"
                        autocomplete="new-password"
                        placeholder="Mínimo de 6 caracteres"
                        required
                    >

                </div>

                <div class="form-group">

                    <label for="newPasswordConfirm">
                        Confirmar nova senha
                    </label>

                    <input
                        id="newPasswordConfirm"
                        class="input"
                        type="password"
                        minlength="6"
                        maxlength="120"
                        autocomplete="new-password"
                        placeholder="Repita a nova senha"
                        required
                    >

                </div>

                <button
                    class="black-btn"
                    type="submit"
                >
                    SALVAR NOVA SENHA
                </button>

            </form>

            <div class="auth-links">
                <button
                    id="forgotBack"
                    class="chip"
                    type="button"
                >
                    Voltar ao login
                </button>
            </div>

        </section>


        <form
            id="registerForm"
            method="POST"
            action="/register"
            hidden
        >

            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token() }}"
            >

            <div class="form-group">

                <label>
                    Nome
                </label>

                <input
                    class="input"
                    type="text"
                    name="username"
                    required
                    minlength="2"
                    maxlength="80"
                    autocomplete="name"
                    placeholder="Nome completo"
                >

            </div>


            <div class="form-group">

                <label>
                    E-mail
                </label>

                <input
                    class="input"
                    type="email"
                    name="email"
                    required
                    maxlength="160"
                    autocomplete="email"
                    placeholder="seu@email.com"
                >

            </div>


            <div class="form-group">

                <label>
                    Telefone
                </label>

                <input
                    class="input"
                    type="tel"
                    name="phone"
                    maxlength="30"
                    autocomplete="tel"
                    placeholder="(00) 00000-0000"
                >

            </div>


            <div class="form-group">

                <label>
                    Senha
                </label>

                <input
                    class="input"
                    type="password"
                    name="password"
                    required
                    minlength="6"
                    maxlength="120"
                    autocomplete="new-password"
                    placeholder="Mínimo de 6 caracteres"
                >

            </div>


            <div class="form-group">

                <label>
                    Confirmar senha
                </label>

                <input
                    class="input"
                    type="password"
                    name="password_confirm"
                    required
                    minlength="6"
                    maxlength="120"
                    autocomplete="new-password"
                    placeholder="Repita sua senha"
                >

            </div>


            <button
                class="black-btn"
                type="submit"
            >
                CRIAR CONTA
            </button>

        </form>


        <div
            id="message"
            class="auth-message"
            role="status"
            aria-live="polite"
        ></div>


        <div class="auth-footer">

            Seus dados ficam separados por conta.
            O acesso de novos usuários depende
            da aprovação do administrador.

        </div>

    </div>

</main>


<script>

const csrf = {{ csrf_token()|tojson }};

const message = document.getElementById("message");

const loginForm = document.getElementById("loginForm");

const loginView = document.getElementById("loginView");

const forgotView = document.getElementById("forgotView");

const registerForm = document.getElementById("registerForm");

const authSwitch = document.getElementById("authSwitch");

const forgotRequestForm = document.getElementById("forgotRequestForm");

const forgotCodeForm = document.getElementById("forgotCodeForm");

const forgotPasswordForm = document.getElementById("forgotPasswordForm");


function showMessage(text, type){

    message.className = "auth-message show" + (type ? " " + type : "");

    message.textContent = text;

}


function clearMessage(){

    message.className = "auth-message";

    message.textContent = "";

}


function setAuthView(view){

    loginView.hidden = view !== "login";

    registerForm.hidden = view !== "register";

    forgotView.hidden = view !== "forgot";

    authSwitch.hidden = view === "forgot";

    document.getElementById("loginTab").classList.toggle("active", view === "login");

    document.getElementById("registerTab").classList.toggle("active", view === "register");

    clearMessage();

}


function showLogin(){

    setAuthView("login");

}


function showRegister(){

    setAuthView("register");

}


function setForgotStep(step){

    forgotRequestForm.hidden = step !== 1;

    forgotCodeForm.hidden = step !== 2;

    forgotPasswordForm.hidden = step !== 3;

    document.getElementById("forgotStep2").classList.toggle("done", step >= 2);

    document.getElementById("forgotStep3").classList.toggle("done", step >= 3);

    const description = document.getElementById("forgotDescription");

    if(step === 1){
        description.textContent =
            "Informe o e-mail ou telefone cadastrado. O código de verificação será enviado somente para o contato registrado na sua conta.";
        document.getElementById("forgotIdentifier").focus();
    }

    if(step === 2){
        description.textContent =
            "Digite o código de 6 dígitos enviado para o contato cadastrado. O código expira em poucos minutos e só pode ser usado uma vez.";
        document.getElementById("forgotCode").value = "";
        document.getElementById("forgotCode").focus();
    }

    if(step === 3){
        description.textContent =
            "Código validado. Defina sua nova senha.";
        document.getElementById("newPassword").focus();
    }

}


async function authPost(url, body){

    const response = await fetch(url, {
        method:"POST",
        credentials:"same-origin",
        headers:{
            "Content-Type":"application/json",
            "X-CSRF-Token":csrf
        },
        body:JSON.stringify(body)
    });

    let data;

    try{
        data = await response.json();
    }catch(err){
        data = {
            ok:false,
            error:"Resposta inválida do servidor."
        };
    }

    return data;

}


async function withButton(form, task){

    const button = form.querySelector('button[type="submit"]');

    if(button){
        button.disabled = true;
    }

    try{
        await task();
    }finally{
        if(button){
            button.disabled = false;
        }
    }

}


loginForm.addEventListener("submit", async e => {

    e.preventDefault();

    const identifier = document.getElementById("loginIdentifier").value.trim();

    const password = document.getElementById("loginPassword").value;

    if(!identifier || !password){
        showMessage("Informe o e-mail ou telefone e a senha.", "error");
        return;
    }

    await withButton(loginForm, async () => {

        showMessage("Entrando...");

        try{

            const data = await authPost("/login", {
                identifier:identifier,
                password:password
            });

            if(!data.ok){
                showMessage(data.error || "Senha incorreta.", "error");
                return;
            }

            location.href = data.redirect || "/dashboard";

        }catch(err){

            showMessage("Não foi possível concluir o login.", "error");

        }

    });

});


document.getElementById("forgotButton").addEventListener("click", () => {

    const typed = document.getElementById("loginIdentifier").value.trim();

    setAuthView("forgot");

    document.getElementById("forgotIdentifier").value = typed;

    setForgotStep(1);

});


document.getElementById("forgotBack").addEventListener("click", () => {

    setForgotStep(1);

    showLogin();

});


async function requestResetCode(){

    const identifier = document.getElementById("forgotIdentifier").value.trim();

    if(!identifier){
        showMessage("Informe o e-mail ou telefone cadastrado.", "error");
        setForgotStep(1);
        return;
    }

    showMessage("Verificando cadastro e enviando código...");

    try{

        const data = await authPost("/forgot-password", {
            identifier:identifier
        });

        if(!data.ok){
            showMessage(data.error || "Não foi possível enviar o código.", "error");
            return;
        }

        setForgotStep(2);

        showMessage(data.message || "Código enviado.", "success");

    }catch(err){

        showMessage("Não foi possível solicitar o código.", "error");

    }

}


forgotRequestForm.addEventListener("submit", async e => {

    e.preventDefault();

    await withButton(forgotRequestForm, requestResetCode);

});


document.getElementById("forgotResend").addEventListener("click", async e => {

    const button = e.currentTarget;

    button.disabled = true;

    try{
        await requestResetCode();
    }finally{
        button.disabled = false;
    }

});


document.getElementById("forgotCode").addEventListener("input", e => {

    e.target.value = e.target.value.replace(/\D/g, "").slice(0, 6);

});


forgotCodeForm.addEventListener("submit", async e => {

    e.preventDefault();

    const code = document.getElementById("forgotCode").value.trim();

    if(!/^\d{6}$/.test(code)){
        showMessage("Digite o código de 6 dígitos.", "error");
        return;
    }

    await withButton(forgotCodeForm, async () => {

        showMessage("Validando código...");

        try{

            const data = await authPost("/forgot-password/verify", {
                code:code
            });

            if(!data.ok){

                showMessage(data.error || "Código inválido.", "error");

                if(data.restart){
                    setForgotStep(1);
                }

                return;
            }

            setForgotStep(3);

            showMessage(data.message || "Código validado.", "success");

        }catch(err){

            showMessage("Não foi possível validar o código.", "error");

        }

    });

});


forgotPasswordForm.addEventListener("submit", async e => {

    e.preventDefault();

    const password = document.getElementById("newPassword").value;

    const passwordConfirm = document.getElementById("newPasswordConfirm").value;

    if(password.length < 6){
        showMessage("A nova senha precisa ter pelo menos 6 caracteres.", "error");
        return;
    }

    if(password !== passwordConfirm){
        showMessage("As senhas não são iguais.", "error");
        return;
    }

    await withButton(forgotPasswordForm, async () => {

        showMessage("Salvando nova senha...");

        try{

            const data = await authPost("/forgot-password/reset", {
                password:password,
                password_confirm:passwordConfirm
            });

            if(!data.ok){

                showMessage(data.error || "Não foi possível alterar a senha.", "error");

                if(data.restart){
                    setForgotStep(1);
                }

                return;
            }

            document.getElementById("newPassword").value = "";

            document.getElementById("newPasswordConfirm").value = "";

            const identifier = document.getElementById("forgotIdentifier").value.trim();

            setForgotStep(1);

            showLogin();

            document.getElementById("loginIdentifier").value = identifier;

            document.getElementById("loginPassword").focus();

            showMessage(data.message || "Senha alterada com sucesso.", "success");

        }catch(err){

            showMessage("Não foi possível alterar a senha.", "error");

        }

    });

});


{% if view == "register" %}
showRegister();
{% endif %}


(function(){

    const canvas = document.getElementById("lucraDataFlow");

    if(!canvas || !canvas.getContext){
        return;
    }

    const ctx = canvas.getContext("2d");

    const reduceMotion =
        window.matchMedia &&
        window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const speedFactor = reduceMotion ? .3 : 1;

    const glyphs = "0123456789ABCDEF$%+-.,<>/=";

    const labels = [
        "R$ 1.284.330",
        "+12,4%",
        "MARGEM 31,8%",
        "0xD4AF37",
        "EBITDA 22,1%",
        "ESTOQUE 4.920",
        "-3,2%",
        "MIX 38%",
        "101101",
        "PRODUÇÃO 18.450",
        "R$ 982.110",
        "IA 360°"
    ];

    let width = 0;
    let height = 0;
    let fontSize = 15;
    let columns = [];
    let streams = [];
    let last = performance.now();
    let accumulator = 0;

    function randomGlyph(){
        return glyphs[Math.floor(Math.random() * glyphs.length)];
    }

    function newColumn(x, randomStart){
        const length = 8 + Math.floor(Math.random() * 16);
        return {
            x:x,
            y:randomStart ? Math.random() * height : -Math.random() * height * .6,
            speed:(40 + Math.random() * 90) * speedFactor,
            length:length,
            chars:Array.from({length:length}, randomGlyph)
        };
    }

    function newStream(randomStart){
        return {
            y:40 + Math.random() * (height - 80),
            x:randomStart ? Math.random() * width : -260,
            speed:(60 + Math.random() * 110) * speedFactor,
            text:labels[Math.floor(Math.random() * labels.length)],
            size:120 + Math.random() * 220
        };
    }

    function resize(){
        const dpr = Math.min(window.devicePixelRatio || 1, 2);
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = Math.floor(width * dpr);
        canvas.height = Math.floor(height * dpr);
        canvas.style.width = width + "px";
        canvas.style.height = height + "px";
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        fontSize = width < 600 ? 12 : 15;
        const spacing = fontSize * 1.9;
        const count = Math.ceil(width / spacing);
        columns = [];
        for(let i = 0; i < count; i++){
            if(Math.random() < .62){
                columns.push(newColumn(i * spacing + spacing / 2, true));
            }
        }
        streams = Array.from({length:width < 600 ? 4 : 8}, () => newStream(true));
    }

    function draw(dt){

        ctx.clearRect(0, 0, width, height);

        ctx.font = "700 " + fontSize + "px 'Courier New', Consolas, monospace";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";

        columns.forEach((col, index) => {

            col.y += col.speed * dt;

            if(Math.random() < .06){
                col.chars[Math.floor(Math.random() * col.length)] = randomGlyph();
            }

            for(let j = 0; j < col.length; j++){
                const y = col.y - j * fontSize * 1.15;
                if(y < -fontSize || y > height + fontSize){
                    continue;
                }
                const fade = 1 - j / col.length;
                if(j === 0){
                    ctx.fillStyle = "rgba(255,255,255," + (.55 * fade + .15) + ")";
                }else if(j < 3){
                    ctx.fillStyle = "rgba(255,244,163," + (.42 * fade) + ")";
                }else{
                    ctx.fillStyle = "rgba(212,175,55," + (.30 * fade) + ")";
                }
                ctx.fillText(col.chars[j], col.x, y);
            }

            if(col.y - col.length * fontSize * 1.15 > height){
                columns[index] = newColumn(col.x, false);
            }

        });

        ctx.textAlign = "left";
        ctx.font = "700 " + (fontSize - 2) + "px 'Courier New', Consolas, monospace";

        streams.forEach((stream, index) => {

            stream.x += stream.speed * dt;

            const gradient = ctx.createLinearGradient(stream.x - stream.size, 0, stream.x, 0);
            gradient.addColorStop(0, "rgba(212,175,55,0)");
            gradient.addColorStop(1, "rgba(255,244,163,.55)");

            ctx.strokeStyle = gradient;
            ctx.lineWidth = 1.2;
            ctx.beginPath();
            ctx.moveTo(stream.x - stream.size, stream.y);
            ctx.lineTo(stream.x, stream.y);
            ctx.stroke();

            ctx.fillStyle = "rgba(255,244,163,.85)";
            ctx.beginPath();
            ctx.arc(stream.x, stream.y, 2.2, 0, Math.PI * 2);
            ctx.fill();

            ctx.fillStyle = "rgba(255,244,163,.40)";
            ctx.fillText(stream.text, stream.x + 8, stream.y - 9);

            if(stream.x - stream.size > width){
                streams[index] = newStream(false);
            }

        });

    }

    function frame(now){

        const dt = Math.min((now - last) / 1000, .1);

        last = now;

        accumulator += dt;

        if(accumulator >= 1 / 40){
            draw(accumulator);
            accumulator = 0;
        }

        requestAnimationFrame(frame);

    }

    resize();

    window.addEventListener("resize", resize);

    requestAnimationFrame(frame);

})();

</script>

{{ global_script|safe }}

</body>
</html>
"""


# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="pt-BR">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<meta
    name="csrf-token"
    content="{{ csrf_token() }}"
>

<meta
    name="theme-color"
    content="#050505"
>

<link
    rel="manifest"
    href="/manifest.json"
>

<title>LUCRA.AI — Visão Geral</title>

{{ style|safe }}

</head>


<body data-session="user">


<header class="topbar">

    <a
        class="brand"
        href="/dashboard"
    >

        <img
            class="brand-logo"
            src="/icon.png"
            alt="LUCRA.AI"
        >

        <span>
            LUCRA
        </span>
        .AI

    </a>


    <div class="top-actions">

        <div class="lupi-shell">
            <div class="lupi-orbit">
                <span class="lupi-core">AI</span>
            </div>
        </div>

        <span>
            {{ user["username"] }}
        </span>

        {% if user["is_admin"] %}

            <a href="/admin">
                ADMIN
            </a>

        {% endif %}

        <a href="/logout">
            Sair
        </a>

    </div>

</header>


<div class="dashboard-layout">


<aside class="sidebar">

    <div class="sidebar-logo">

        <img
            src="/icon.png"
            alt="LUCRA.AI"
        >

        <div>
            LUCRA.AI
            <small
                style="display:block;color:#999;"
            >
                Executive Vision
            </small>
        </div>

    </div>


    <nav class="sidebar-menu">

        <a
            class="active"
            href="#visao"
        >
            Visão Geral
        </a>

        <a href="#dados">
            Dados
        </a>

        <a href="#chat">
            IA Estratégica
        </a>

        <a href="#exportar">
            Exportar
        </a>

        <a href="/logout">
            Sair
        </a>

    </nav>

</aside>


<main class="dashboard-main">


<section
    id="visao"
    class="hero"
>

    <div class="eyebrow">
        PRODUTO | PERFORMANCE | ESTRATÉGIA
    </div>

    <h1>
        Visão 360°
    </h1>

    <p class="muted">
        Inteligência executiva baseada nos
        dados disponíveis da empresa.
    </p>


    <div
        style="
        display:flex;
        gap:7px;
        flex-wrap:wrap;
        margin-top:18px;
        "
    >

        <div class="loop-number">
            <span>01</span>
        </div>

        <div class="loop-number">
            <span>02</span>
        </div>

        <div class="loop-number">
            <span>03</span>
        </div>

        <div class="loop-number">
            <span>∞</span>
        </div>

    </div>

</section>


<section class="metric-grid">


    <div class="metric-card featured">

        <span>
            Valor Total
        </span>

        <strong id="metricTotal">
            {{ metrics["Valor Total"]|money }}
        </strong>

    </div>


    <div class="metric-card">

        <span>
            Receita Comercial
        </span>

        <strong id="metricRevenue">
            {{ metrics["Receita Comercial"]|money }}
        </strong>

    </div>


    <div class="metric-card">

        <span>
            Custo Operacional
        </span>

        <strong id="metricCost">
            {{ metrics["Custo Operacional"]|money }}
        </strong>

    </div>


    <div class="metric-card">

        <span>
            Ativo em Estoque
        </span>

        <strong id="metricStock">
            {{ metrics["Ativo em Estoque"]|money }}
        </strong>

    </div>


</section>


<section class="metric-grid">


    <div class="metric-card">

        <span>
            Volume de Produção
        </span>

        <strong>
            {{ "%.2f"|format(metrics["Volume de Produção"]) }}
        </strong>

    </div>


    <div class="metric-card">

        <span>
            Mix de Produtos
        </span>

        <strong>
            {{ "%.2f"|format(metrics["Mix de Produtos"]) }}
        </strong>

    </div>


    <div class="metric-card">

        <span>
            Performance
        </span>

        <strong>
            {{ "%.2f"|format(metrics["Performance"]) }}
        </strong>

    </div>


    <div class="metric-card">

        <span>
            Estratégia
        </span>

        <strong>
            {{ "%.2f"|format(metrics["Estratégia"]) }}
        </strong>

    </div>


</section>


<div class="two-columns">


<section
    id="dados"
    class="panel"
>

    <div class="row space">

        <div>

            <div class="eyebrow">
                FONTES
            </div>

            <h2>
                Dados da empresa
            </h2>

            <p class="muted">
                Todos os arquivos desta conta
                podem ser usados pela IA.
            </p>

        </div>

    </div>


    <div class="upload-box">

        <form
            id="uploadForm"
            enctype="multipart/form-data"
        >

            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token() }}"
            >

            <div class="form-group">

                <label>
                    Adicionar CSV / XLS / XLSX
                </label>

                <input
                    id="fileInput"
                    class="input"
                    type="file"
                    name="file"
                    accept=".csv,.xls,.xlsx"
                    required
                >

            </div>


            <div class="row">

                <button
                    class="gold-btn"
                    type="submit"
                >
                    Incorporar arquivo
                </button>

                <button
                    class="secondary-btn"
                    type="button"
                    onclick="openFolderPicker()"
                >
                    Incorporar pasta
                </button>

            </div>


            <input
                id="folderInput"
                type="file"
                webkitdirectory
                directory
                multiple
                style="display:none;"
            >

            <div
                class="progress"
                id="uploadProgressBox"
                style="display:none;"
            >
                <span id="uploadProgress"></span>
            </div>

        </form>

    </div>


    <div
        id="sourceList"
        class="source-list"
        style="margin-top:14px;"
    >

        {% if sources %}

            {% for source in sources %}

                <div class="source-item">

                    <div>

                        <strong>
                            {{ source["relative_path"] }}
                        </strong>

                        <small>
                            {{ source["rows"] }}
                            linha(s)
                            —
                            {{ source["source_type"] }}
                        </small>

                    </div>

                    <button
                        class="danger-btn"
                        onclick="deleteSource({{ source['id'] }})"
                    >
                        Excluir
                    </button>

                </div>

            {% endfor %}

        {% else %}

            <div class="empty">
                Nenhum arquivo incorporado.
            </div>

        {% endif %}

    </div>

</section>


<section
    id="exportar"
    class="panel"
>

    <div class="eyebrow">
        CONTROLE
    </div>

    <h2>
        Exportação
    </h2>

    <p class="muted">
        Exporte os dados e análises
        disponíveis nesta conta.
    </p>


    <a
        class="black-btn"
        href="/export"
        style="
        display:inline-block;
        margin-top:8px;
        "
    >
        Exportar Excel
    </a>


    <div
        style="
        margin-top:25px;
        padding-top:20px;
        border-top:1px solid #eee;
        "
    >

        <strong>
            Aplicativos
        </strong>

        <p
            class="muted"
            style="font-size:12px;"
        >
            Os arquivos APK e EXE só ficam
            disponíveis depois que forem
            publicados pelo administrador.
        </p>


        <div class="row">

            <a
                class="secondary-btn"
                href="/download/android"
            >
                Android APK
            </a>

            <a
                class="secondary-btn"
                href="/download/windows"
            >
                Windows EXE
            </a>

        </div>

    </div>

</section>

</div>


<section id="chat" class="panel ai-panel" style="margin-top:18px;">
<div class="ai-shell" id="aiShell">
    <aside class="ai-history" id="aiHistory">
        <div class="ai-history-head">
            <strong>Conversas</strong>
            <button class="ai-new-btn" type="button" onclick="newConversation()">＋ Nova conversa</button>
        </div>
        <div class="ai-history-list" id="conversationList">
            <div class="ai-history-empty">Nenhuma conversa salva ainda.</div>
        </div>
    </aside>
    <div class="ai-chat">
        <div class="ai-chat-head">
            <button class="ai-history-toggle" type="button" onclick="toggleHistory()" aria-label="Conversas">☰</button>
            <div class="ai-chat-title">
                <strong id="chatTitle">Nova conversa</strong>
                <small>LUCRA.AI · Inteligência executiva</small>
            </div>
            <button class="ai-emoji-btn" type="button" onclick="toggleEmojiLevel()">✨ Emojis</button>
        </div>
        <div id="chatMessages" class="ai-messages"></div>
        <div class="ai-quick">
            <button class="quick-btn" type="button" onclick="quickAsk('Faça um resumo executivo da empresa.')">📊 Resumo executivo</button>
            <button class="quick-btn" type="button" onclick="quickAsk('Quantos paletes foram armazenados no A01?')">🏬 Armazém A01</button>
            <button class="quick-btn" type="button" onclick="quickAsk('Qual é a Receita Comercial?')">💵 Receita</button>
            <button class="quick-btn" type="button" onclick="quickAsk('Qual é o Custo Operacional?')">📉 Custos</button>
            <button class="quick-btn" type="button" onclick="quickAsk('Qual é o valor do estoque?')">📦 Estoque</button>
            <button class="quick-btn" type="button" onclick="quickAsk('Calcule o lucro com os dados disponíveis.')">💰 Lucro</button>
        </div>
        <div class="ai-sheet" id="companySheet">
            {% if company_sheet %}
            <div class="ai-sheet-pinned">
                <span>📌</span>
                <div>
                    <strong>Planilha da empresa</strong>
                    <small>{{ company_sheet["relative_path"] }} · {{ company_sheet["rows"] }} linha(s)</small>
                </div>
                <button class="ai-trash" type="button" title="Excluir planilha" onclick="deleteCompanySheet({{ company_sheet['id'] }})">🗑️</button>
            </div>
            {% else %}
            <button class="ai-sheet-add" type="button" onclick="pickCompanySheet()">📎 Adicionar planilha da empresa</button>
            {% endif %}
            <input id="companySheetInput" type="file" accept="{{ sheet_accept }}" style="display:none;">
        </div>
        <div class="ai-composer">
            <textarea id="chatInput" class="ai-input" placeholder="Pergunte qualquer coisa sobre a empresa" rows="1" onkeydown="handleChatKey(event)"></textarea>
            <div class="ai-composer-row">
                <button class="ai-plus" type="button" onclick="pickCompanySheet()" title="Adicionar planilha da empresa">+</button>
                <button id="sendChat" class="ai-send" type="button" onclick="sendChat()" aria-label="Enviar">↑</button>
            </div>
        </div>
    </div>
</div>
</section>


</main>

</div>


<script>

let emojiLevel = 0;
let currentConversation = null;
const chatUserName = {{ user["username"]|tojson }};
const hasCompanySheet = {{ "true" if company_sheet else "false" }};
function chatBox(){ return document.getElementById("chatMessages"); }
function scrollChat(){ const box = chatBox(); box.scrollTop = box.scrollHeight; }
function addMessage(text, type){
    const row = document.createElement("div");
    row.className = "ai-row " + type;
    if(type === "ai"){
        const tag = document.createElement("span");
        tag.className = "ai-tag";
        tag.textContent = "LUCRA.AI";
        row.appendChild(tag);
    }
    const bubble = document.createElement("div");
    bubble.className = "message " + type;
    bubble.textContent = text;
    row.appendChild(bubble);
    chatBox().appendChild(row);
    scrollChat();
    return bubble;
}
function addTyping(){
    const bubble = addMessage("", "ai");
    bubble.classList.add("ai-typing");
    for(let i = 0; i < 3; i++){ bubble.appendChild(document.createElement("span")); }
    return bubble.parentElement;
}
function typeText(element, text){
    return new Promise(resolve => {
        const value = String(text || "");
        const run = String(Date.now() + Math.random());
        element.dataset.run = run;
        element.textContent = "";
        const words = value.split(" ");
        const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        if(reduce || words.length > 350){ element.textContent = value; scrollChat(); resolve(); return; }
        let index = 0;
        function step(){
            if(element.dataset.run !== run || index >= words.length){ resolve(); return; }
            const span = document.createElement("span");
            span.className = "ai-word";
            span.textContent = (index ? " " : "") + words[index];
            element.appendChild(span);
            index++;
            scrollChat();
            setTimeout(step, 22 + Math.random() * 38);
        }
        step();
    });
}
function addAnswer(data, animate){
    const detailed = data.detailed || data.response || "Não foi possível gerar uma resposta.";
    const summary = data.summary || detailed;
    const bubble = addMessage("", "ai");
    if(!data.has_modes){
        if(animate){ return typeText(bubble, detailed); }
        bubble.textContent = detailed;
        return Promise.resolve();
    }
    const modes = document.createElement("div");
    modes.className = "ai-modes";
    const summaryButton = document.createElement("button");
    summaryButton.type = "button";
    summaryButton.className = "ai-mode-btn";
    summaryButton.textContent = "⚡ Resumido";
    const detailedButton = document.createElement("button");
    detailedButton.type = "button";
    detailedButton.className = "ai-mode-btn";
    detailedButton.textContent = "📋 Detalhado";
    modes.append(summaryButton, detailedButton);
    bubble.parentElement.appendChild(modes);
    function choose(mode){
        summaryButton.classList.toggle("active", mode === "summary");
        detailedButton.classList.toggle("active", mode === "detailed");
        bubble.classList.remove("ai-awaiting");
        typeText(bubble, mode === "summary" ? summary : detailed);
    }
    summaryButton.addEventListener("click", () => choose("summary"));
    detailedButton.addEventListener("click", () => choose("detailed"));
    if(animate){
        bubble.classList.add("ai-awaiting");
        bubble.textContent = "Tenho a resposta! 😉 Como você prefere ver?";
    }else{
        detailedButton.classList.add("active");
        bubble.textContent = detailed;
    }
    scrollChat();
    return Promise.resolve();
}
function setChatTitle(title){ document.getElementById("chatTitle").textContent = title || "Nova conversa"; }
function showWelcome(){
    let text = `Olá, ${chatUserName}! 👋 Eu sou a LUCRA.AI, sua assistente executiva.

Me pergunte sobre estoque, armazéns, vendas, custos ou lucro. Nas respostas com números, você escolhe ⚡ Resumido ou 📋 Detalhado.`;
    if(!hasCompanySheet){
        text += `

📎 Para começar, adicione a planilha da empresa logo abaixo. Funciona no celular e no computador.`;
    }
    addMessage(text, "ai");
}
function toggleHistory(force){
    const shell = document.getElementById("aiShell");
    shell.classList.toggle("history-open", force);
}
function renderConversations(items){
    const list = document.getElementById("conversationList");
    list.innerHTML = "";
    if(!items.length){
        const empty = document.createElement("div");
        empty.className = "ai-history-empty";
        empty.textContent = "Nenhuma conversa salva ainda.";
        list.appendChild(empty);
        return;
    }
    items.forEach(item => {
        const row = document.createElement("div");
        row.className = "ai-history-item" + (item.id === currentConversation ? " active" : "");
        const open = document.createElement("button");
        open.type = "button";
        open.className = "ai-history-open";
        const title = document.createElement("span");
        title.textContent = item.title;
        const date = document.createElement("small");
        const parsed = new Date(item.updated_at);
        date.textContent = isNaN(parsed) ? "" : parsed.toLocaleString("pt-BR", {day:"2-digit", month:"2-digit", hour:"2-digit", minute:"2-digit"});
        open.append(title, date);
        open.addEventListener("click", () => openConversation(item.id));
        const del = document.createElement("button");
        del.type = "button";
        del.className = "ai-trash";
        del.title = "Excluir conversa";
        del.textContent = "🗑️";
        del.addEventListener("click", event => deleteConversation(item.id, event));
        row.append(open, del);
        list.appendChild(row);
    });
}
async function loadConversations(){
    try{
        const data = await apiFetch("/api/conversations");
        renderConversations(data.conversations || []);
    }catch(error){}
}
async function openConversation(id){
    try{
        const data = await apiFetch("/api/conversations/" + id);
        currentConversation = id;
        setChatTitle(data.title);
        chatBox().innerHTML = "";
        (data.messages || []).forEach(item => {
            addMessage(item.message, "user");
            addAnswer({summary:item.summary, detailed:item.response, has_modes:!!item.summary && item.summary !== item.response}, false);
        });
        toggleHistory(false);
        loadConversations();
    }catch(error){
        toast(error.message);
    }
}
function newConversation(){
    currentConversation = null;
    setChatTitle("Nova conversa");
    chatBox().innerHTML = "";
    showWelcome();
    toggleHistory(false);
    loadConversations();
    document.getElementById("chatInput").focus();
}
async function deleteConversation(id, event){
    event.stopPropagation();
    if(!confirm("Excluir esta conversa?")){ return; }
    try{
        await apiFetch("/api/conversations/" + id, {method:"DELETE"});
        if(id === currentConversation){ newConversation(); } else { loadConversations(); }
    }catch(error){
        toast(error.message);
    }
}
function handleChatKey(event){
    if(event.key === "Enter" && !event.shiftKey){
        event.preventDefault();
        sendChat();
    }
}
function quickAsk(text){
    document.getElementById("chatInput").value = text;
    sendChat();
}
function toggleEmojiLevel(){
    emojiLevel++;
    if(emojiLevel > 3){ emojiLevel = 0; }
    const levels = ["Emojis extras desativados.", "Emojis básicos ativados.", "Mais emojis ativados.", "Modo máximo de emojis ativado."];
    toast(levels[emojiLevel]);
}
function autoGrow(input){
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, 140) + "px";
}
document.getElementById("chatInput").addEventListener("input", function(){ autoGrow(this); });
async function sendChat(){
    const input = document.getElementById("chatInput");
    const button = document.getElementById("sendChat");
    const message = input.value.trim();
    if(!message){ return; }
    addMessage(message, "user");
    input.value = "";
    autoGrow(input);
    button.disabled = true;
    const loading = addTyping();
    try{
        const data = await apiFetch("/api/chat", {
            method:"POST",
            body:JSON.stringify({message:message, emoji_level:emojiLevel, conversation_id:currentConversation})
        });
        loading.remove();
        if(data.conversation_id){
            currentConversation = data.conversation_id;
            setChatTitle(data.conversation_title);
        }
        addAnswer(data, true);
        loadConversations();
    }catch(error){
        loading.remove();
        addMessage(error.message || "Ocorreu um erro.", "ai");
    }finally{
        button.disabled = false;
        input.focus();
    }
}
function pickCompanySheet(){
    if(hasCompanySheet){
        toast("Já existe uma planilha fixada. Exclua pela lixeira 🗑️ para trocar.");
        return;
    }
    document.getElementById("companySheetInput").click();
}
document.getElementById("companySheetInput").addEventListener("change", async function(){
    if(!this.files.length){ return; }
    const formData = new FormData();
    formData.append("file", this.files[0]);
    formData.append("source_type", "empresa");
    formData.append("csrf_token", getCsrfToken());
    toast("Enviando planilha da empresa...");
    try{
        await apiFetch("/upload", {method:"POST", body:formData});
        toast("📌 Planilha da empresa salva!");
        setTimeout(() => location.reload(), 600);
    }catch(error){
        toast(error.message);
    }
    this.value = "";
});
async function deleteCompanySheet(id){
    if(!confirm("Excluir a planilha da empresa? Você poderá adicionar outra depois.")){ return; }
    try{
        await apiFetch("/api/source/" + id, {method:"DELETE"});
        toast("Planilha excluída.");
        setTimeout(() => location.reload(), 500);
    }catch(error){
        toast(error.message);
    }
}
showWelcome();
loadConversations();


async function deleteSource(
    id
){

    if(
        !confirm(
            "Excluir esta fonte?"
        )
    ){
        return;
    }

    try{

        await apiFetch(
            "/api/source/" + id,
            {
                method:"DELETE"
            }
        );

        location.reload();

    }catch(error){

        toast(
            error.message
        );

    }

}


function openFolderPicker(){

    const input =
        document.getElementById(
            "folderInput"
        );

    input.click();

}


document.getElementById(
    "uploadForm"
).addEventListener(
    "submit",
    async function(event){

        event.preventDefault();

        const input =
            document.getElementById(
                "fileInput"
            );

        if(
            !input.files.length
        ){
            toast(
                "Selecione um arquivo."
            );
            return;
        }

        const formData =
            new FormData();

        formData.append(
            "file",
            input.files[0]
        );

        const csrf =
            getCsrfToken();

        formData.append(
            "csrf_token",
            csrf
        );

        const progressBox =
            document.getElementById(
                "uploadProgressBox"
            );

        const progress =
            document.getElementById(
                "uploadProgress"
            );

        progressBox.style.display =
            "block";

        progress.style.width =
            "20%";

        try{

            const response =
                await fetch(
                    "/upload",
                    {
                        method:"POST",
                        body:formData,
                        headers:{
                            "X-CSRF-Token":csrf
                        }
                    }
                );

            const data =
                await response.json();

            if(!response.ok){
                throw new Error(
                    data.error ||
                    "Falha no envio."
                );
            }

            progress.style.width =
                "100%";

            toast(
                "Arquivo incorporado com sucesso."
            );

            setTimeout(
                () => location.reload(),
                500
            );

        }catch(error){

            progress.style.width =
                "0%";

            toast(
                error.message
            );

        }

    }
);


document.getElementById(
    "folderInput"
).addEventListener(
    "change",
    async function(){

        const files =
            [...this.files];

        if(!files.length){
            return;
        }

        const validFiles =
            files.filter(
                file => {
                    const name =
                        file.name.toLowerCase();

                    return (
                        name.endsWith(".csv")
                        || name.endsWith(".xlsx")
                        || name.endsWith(".xls")
                    );
                }
            );

        if(!validFiles.length){

            toast(
                "A pasta não possui CSV, XLS ou XLSX."
            );

            return;
        }

        const progressBox =
            document.getElementById(
                "uploadProgressBox"
            );

        const progress =
            document.getElementById(
                "uploadProgress"
            );

        progressBox.style.display =
            "block";

        let done = 0;

        for(
            const file of validFiles
        ){

            const formData =
                new FormData();

            formData.append(
                "file",
                file
            );

            formData.append(
                "relative_path",
                file.webkitRelativePath
                || file.name
            );

            formData.append(
                "source_type",
                "folder"
            );

            formData.append(
                "csrf_token",
                getCsrfToken()
            );

            try{

                const response =
                    await fetch(
                        "/upload",
                        {
                            method:"POST",
                            body:formData,
                            headers:{
                                "X-CSRF-Token":
                                    getCsrfToken()
                            }
                        }
                    );

                if(!response.ok){
                    console.warn(
                        await response.text()
                    );
                }

            }catch(error){

                console.error(
                    error
                );

            }

            done++;

            progress.style.width =
                (
                    done /
                    validFiles.length *
                    100
                ) + "%";
        }

        toast(
            `${done} arquivo(s) processado(s).`
        );

        setTimeout(
            () => location.reload(),
            700
        );

    }
);

</script>


{{ global_script|safe }}

</body>
</html>
"""


# ============================================================
# ADMIN
# ============================================================

ADMIN_HTML = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="csrf-token" content="{{ csrf_token() }}">
<meta name="theme-color" content="#050505">
<title>LUCRA.AI — Administração</title>
{{ style|safe }}
</head>
<body>
<header class="topbar">
    <a class="brand" href="/dashboard">
        <img class="brand-logo" src="/icon.png" alt="LUCRA.AI">
        <span>LUCRA</span>.AI
    </a>
    <div class="top-actions">
        <a href="/dashboard">Dashboard</a>
        <a href="/logout">Sair</a>
    </div>
</header>
<main class="shell">
<section class="hero admin-hero">
    <div class="eyebrow">ADMINISTRAÇÃO</div>
    <div class="chefe-stage" id="chefeStage" role="button" tabindex="0" aria-label="BEM VINDO CHEFE">
        <canvas id="chefeCanvas"></canvas>
        <h1 class="sr-only">BEM VINDO CHEFE</h1>
        <div class="chefe-hint" id="chefeHint">TOQUE NO TEXTO</div>
    </div>
    <p class="muted">Controle de acesso da LUCRA.AI: aceite, recuse ou remova logins.</p>
</section>
<section class="panel">
    <div class="admin-tabs" role="tablist">
        <button type="button" class="admin-tab {% if active_tab != 'aceitos' %}active{% endif %}" data-tab="solicitacoes">
            Solicitações <span class="count">{{ pending_users|length }}</span>
        </button>
        <button type="button" class="admin-tab {% if active_tab == 'aceitos' %}active{% endif %}" data-tab="aceitos">
            Logins aceitos <span class="count">{{ accepted_users|length }}</span>
        </button>
    </div>
    <div class="admin-pane {% if active_tab != 'aceitos' %}active{% endif %}" id="pane-solicitacoes">
        <p class="muted">Todos que tentaram acessar a LUCRA IA. Aceite ou recuse.</p>
        <div class="admin-user-list">
        {% for item in pending_users %}
            <div class="admin-user">
                <div class="admin-avatar">{{ item["username"][:1]|upper }}</div>
                <div class="admin-user-info">
                    <strong>Usuário: {{ item["username"] }}</strong>
                    <small>{{ item["email"] }}{% if item["phone"] %} · {{ item["phone"] }}{% endif %} · {{ item["created_at"] }}</small>
                </div>
                <div class="admin-user-actions">
                    <form method="POST" action="/admin/approve/{{ item['id'] }}">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <button class="gold-btn small-btn" type="submit">✅ Aceitar</button>
                    </form>
                    <form method="POST" action="/admin/delete/{{ item['id'] }}">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <button class="danger-btn" type="submit" onclick="return confirm('Recusar e excluir esta solicitação?');">✖ Recusar</button>
                    </form>
                </div>
            </div>
        {% else %}
            <div class="empty">Nenhuma solicitação de acesso no momento.</div>
        {% endfor %}
        </div>
    </div>
    <div class="admin-pane {% if active_tab == 'aceitos' %}active{% endif %}" id="pane-aceitos">
        <p class="muted">Logins aceitos ficam salvos aqui. A lixeira remove o acesso e desconecta o usuário.</p>
        <div class="admin-user-list">
        {% for item in accepted_users %}
            <div class="admin-user">
                <div class="admin-avatar">{{ item["username"][:1]|upper }}</div>
                <div class="admin-user-info">
                    <strong>{{ item["username"] }}</strong>
                    <small>{{ item["email"] }}{% if item["phone"] %} · {{ item["phone"] }}{% endif %}</small>
                </div>
                <div class="admin-user-actions">
                    <form method="POST" action="/admin/revoke/{{ item['id'] }}">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <button class="admin-trash" type="submit" title="Excluir acesso" onclick="return confirm('Remover o acesso deste usuário? Ele verá: Você foi desconectado da LUCRA IA!');">🗑️</button>
                    </form>
                </div>
            </div>
        {% else %}
            <div class="empty">Nenhum login aceito ainda.</div>
        {% endfor %}
        </div>
    </div>
</section>
</main>
<script>
document.querySelectorAll(".admin-tab").forEach(tab => {
    tab.addEventListener("click", () => {
        document.querySelectorAll(".admin-tab").forEach(item => item.classList.toggle("active", item === tab));
        document.querySelectorAll(".admin-pane").forEach(pane => pane.classList.toggle("active", pane.id === "pane-" + tab.dataset.tab));
    });
});
(function(){
    const stage = document.getElementById("chefeStage");
    const canvas = document.getElementById("chefeCanvas");
    const hint = document.getElementById("chefeHint");
    if(!stage || !canvas){ return; }
    const ctx = canvas.getContext("2d");
    const LINES = ["BEM", "VINDO", "CHEFE"];
    const COLORS = ["#D4AF37", "#FFF4A3", "#E8C766"];
    let grains = [];
    let state = "idle";
    let W = 0, H = 0, grain = 6, floor = [], returnTimer = null, frame = 0;
    function build(){
        const dpr = Math.min(window.devicePixelRatio || 1, 2);
        const rect = stage.getBoundingClientRect();
        W = Math.max(200, Math.floor(rect.width));
        H = Math.max(160, Math.floor(rect.height));
        canvas.width = W * dpr;
        canvas.height = H * dpr;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        grain = W < 520 ? 4 : 6;
        const off = document.createElement("canvas");
        off.width = W;
        off.height = H;
        const o = off.getContext("2d");
        let size = Math.min(H / (LINES.length + 0.6), W / 4);
        o.font = "900 " + size + "px Arial Black, Impact, sans-serif";
        const widest = Math.max.apply(null, LINES.map(line => o.measureText(line).width));
        if(widest > W * 0.86){
            size = size * W * 0.86 / widest;
            o.font = "900 " + size + "px Arial Black, Impact, sans-serif";
        }
        o.fillStyle = "#fff";
        o.textAlign = "center";
        o.textBaseline = "middle";
        const lineHeight = size * 1.02;
        const startY = (H - lineHeight * LINES.length) / 2 + lineHeight / 2;
        LINES.forEach((line, index) => o.fillText(line, W / 2, startY + index * lineHeight));
        const data = o.getImageData(0, 0, W, H).data;
        grains = [];
        for(let y = 0; y < H; y += grain){
            for(let x = 0; x < W; x += grain){
                if(data[(y * W + x) * 4 + 3] > 128){
                    grains.push({hx:x, hy:y, x:x, y:y, vx:0, vy:0, ch:Math.random() < .5 ? "0" : "1", c:Math.floor(Math.random() * 3), done:false, delay:0});
                }
            }
        }
        state = "idle";
        if(hint){ hint.textContent = "TOQUE NO TEXTO"; }
    }
    function fall(){
        state = "falling";
        floor = new Array(Math.ceil(W / grain) + 2).fill(H);
        grains.sort((a, b) => b.hy - a.hy);
        grains.forEach(g => {
            g.vx = (Math.random() - .5) * 2.2;
            g.vy = -Math.random() * 2.5;
            g.done = false;
            g.delay = Math.floor(Math.random() * 12);
        });
        if(hint){ hint.textContent = "TOQUE PARA RECONSTRUIR"; }
        clearTimeout(returnTimer);
        returnTimer = setTimeout(rebuild, 3000);
    }
    function rebuild(){
        clearTimeout(returnTimer);
        state = "rebuilding";
        grains.forEach(g => {
            g.done = false;
            g.delay = Math.floor((g.hx / W) * 28);
        });
        if(hint){ hint.textContent = "TOQUE NO TEXTO"; }
    }
    function update(){
        if(state === "falling"){
            grains.forEach(g => {
                if(g.done){ return; }
                if(g.delay > 0){ g.delay--; return; }
                g.vy += 0.45;
                g.x += g.vx;
                g.y += g.vy;
                if(g.x < 0){ g.x = 0; g.vx *= -0.4; }
                if(g.x > W - grain){ g.x = W - grain; g.vx *= -0.4; }
                let col = Math.max(0, Math.min(floor.length - 1, Math.round(g.x / grain)));
                if(g.y >= floor[col] - grain){
                    const left = col > 0 ? floor[col - 1] : -1;
                    const right = col < floor.length - 1 ? floor[col + 1] : -1;
                    if(left > floor[col] + grain && left >= right){ col -= 1; }
                    else if(right > floor[col] + grain){ col += 1; }
                    g.x = col * grain;
                    g.y = floor[col] - grain;
                    floor[col] -= grain * 0.92;
                    g.done = true;
                }
            });
        }else if(state === "rebuilding"){
            let moving = false;
            grains.forEach(g => {
                if(g.delay > 0){ g.delay--; moving = true; return; }
                g.x += (g.hx - g.x) * 0.16;
                g.y += (g.hy - g.y) * 0.16;
                if(Math.abs(g.hx - g.x) > 0.5 || Math.abs(g.hy - g.y) > 0.5){ moving = true; }
                else { g.x = g.hx; g.y = g.hy; }
            });
            if(!moving){ state = "idle"; }
        }
    }
    function draw(){
        ctx.clearRect(0, 0, W, H);
        ctx.font = "700 " + Math.round(grain * 1.35) + "px monospace";
        ctx.textBaseline = "top";
        for(let c = 0; c < 3; c++){
            ctx.fillStyle = COLORS[c];
            for(let i = 0; i < grains.length; i++){
                const g = grains[i];
                if(g.c === c){ ctx.fillText(g.ch, g.x, g.y); }
            }
        }
    }
    function loop(){
        frame++;
        if(state === "idle" && frame % 4 === 0){
            for(let i = 0; i < Math.max(1, grains.length / 120); i++){
                const g = grains[Math.floor(Math.random() * grains.length)];
                if(g){ g.ch = g.ch === "0" ? "1" : "0"; }
            }
        }
        update();
        draw();
        requestAnimationFrame(loop);
    }
    function toggle(){
        if(state === "idle"){ fall(); } else { rebuild(); }
    }
    stage.addEventListener("click", toggle);
    stage.addEventListener("keydown", event => {
        if(event.key === "Enter" || event.key === " "){ event.preventDefault(); toggle(); }
    });
    let resizeTimer = null;
    window.addEventListener("resize", () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(build, 200);
    });
    build();
    requestAnimationFrame(loop);
})();
</script>
{{ global_script|safe }}
</body>
</html>
"""


# ============================================================
# FILTRO DE MOEDA PARA JINJA
# ============================================================

@app.template_filter("money")
def money_filter(
    value
):
    return money(
        value
    )


# ============================================================
# PÁGINA DE LOGIN
# ============================================================

@app.route(
    "/",
    methods=["GET"],
)
def index():

    user = current_user()

    if user:

        if int(
            user["is_admin"]
        ):

            return redirect(
                url_for(
                    "admin_page"
                )
            )

        if int(
            user["approved"]
        ):

            return redirect(
                url_for(
                    "dashboard"
                )
            )

    return redirect(
        url_for(
            "login_page"
        )
    )


@app.route(
    "/login",
    methods=["GET", "POST"],
)
def login_page():

    if request.method == "GET":

        user = current_user()

        if user:

            if int(
                user["is_admin"]
            ):

                return redirect(
                    url_for(
                        "admin_page"
                    )
                )

            if int(
                user["approved"]
            ):

                return redirect(
                    url_for(
                        "dashboard"
                    )
                )

        return render_template_string(
            LOGIN_HTML,
            style=PAGE_STYLE,
            global_script=GLOBAL_SCRIPT,
            error=None,
            pending=bool(
                request.args.get(
                    "pending"
                )
            ),
            kicked=bool(
                request.args.get(
                    "kicked"
                )
            ),
        )

    payload = request.get_json(
        silent=True
    )

    wants_json = isinstance(
        payload,
        dict,
    )

    if wants_json:

        identifier = str(
            payload.get(
                "identifier",
                "",
            )
        ).strip()

        password = str(
            payload.get(
                "password",
                "",
            )
        )

    else:

        identifier = (
            request.form.get(
                "identifier",
                "",
            )
            or request.form.get(
                "email",
                "",
            )
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

    def login_failed(
        error,
        pending=False,
        status=401,
    ):

        if wants_json:

            return jsonify(
                {
                    "ok": False,
                    "error": error,
                    "pending": pending,
                }
            ), status

        return render_template_string(
            LOGIN_HTML,
            style=PAGE_STYLE,
            global_script=GLOBAL_SCRIPT,
            error=error,
            pending=pending,
        ), status

    if not identifier or not password:

        return login_failed(
            "Informe o e-mail ou telefone e a senha.",
            status=400,
        )

    ip_key = "ip:" + client_ip()

    id_key = "id:" + identifier[:160].lower()

    if rate_blocked(
        "login",
        ip_key,
    ) or rate_blocked(
        "login_id",
        id_key,
    ):
        return login_failed(
            "🔒 Muitas tentativas de login. "
            "Aguarde alguns minutos e tente novamente.",
            status=429,
        )

    connection = db()

    user = find_user_by_identifier(
        connection,
        identifier[:160],
    )

    if not user or not verify_password(
        password,
        user["password_hash"],
    ):

        connection.close()

        rate_hit(
            "login",
            ip_key,
        )

        rate_hit(
            "login_id",
            id_key,
        )

        return login_failed(
            "E-mail/telefone ou senha incorretos. "
            "Se esqueceu sua senha, use \"Esqueci minha senha\"."
        )

    if not int(
        user["approved"]
    ):

        if int(
            user["revoked"] or 0
        ):

            connection.execute(
                """
                UPDATE users
                SET revoked = 0
                WHERE id = ?
                """,
                (
                    user["id"],
                ),
            )

            connection.commit()
            connection.close()

            return login_failed(
                KICKED_MESSAGE
                + " Sua nova solicitação de acesso foi enviada ao administrador.",
                pending=True,
                status=403,
            )

        connection.close()

        return login_failed(
            "Sua conta ainda aguarda aprovação do administrador.",
            pending=True,
            status=403,
        )

    session.clear()

    rate_clear(
        "login_id",
        id_key,
    )

    session.permanent = True

    session["user_id"] = user[
        "id"
    ]

    session["csrf_token"] = secrets.token_urlsafe(
        32
    )

    session["ua"] = ua_fingerprint()

    connection.execute(
        """
        INSERT INTO login_history
        (
            user_id,
            identifier,
            login_at
        )
        VALUES (?, ?, ?)
        """,
        (
            user["id"],
            identifier[:160],
            datetime.now().isoformat(
                timespec="seconds"
            ),
        ),
    )

    connection.commit()
    connection.close()

    destination = url_for(
        "admin_page"
        if int(
            user["is_admin"]
        )
        else "dashboard"
    )

    if wants_json:

        return jsonify(
            {
                "ok": True,
                "redirect": destination,
            }
        )

    return redirect(
        destination
    )


# ============================================================
# CRIAÇÃO DE CONTA
# ============================================================

@app.route(
    "/register",
    methods=["POST"],
)
def register():

    username = (
        request.form.get(
            "username",
            "",
        )
        .strip()
    )

    email = (
        request.form.get(
            "email",
            "",
        )
        .strip()
        .lower()
    )

    phone = (
        request.form.get(
            "phone",
            "",
        )
        .strip()
    )

    password = request.form.get(
        "password",
        "",
    )

    password_confirm = request.form.get(
        "password_confirm",
        "",
    )

    if len(username) < 2:

        error = "Informe um nome válido."

    elif not re.match(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        email,
    ):

        error = "Informe um e-mail válido."

    elif len(password) < 6:

        error = "A senha precisa ter pelo menos 6 caracteres."

    elif password != password_confirm:

        error = "As senhas não são iguais."

    elif email == ADMIN_EMAIL:

        error = "Este e-mail é reservado para o administrador."

    elif phone and not (
        8 <= len(normalize_phone(phone)) <= 15
    ):

        error = "Informe um telefone válido."

    else:

        error = None

    if error:

        return render_template_string(
            LOGIN_HTML,
            style=PAGE_STYLE,
            global_script=GLOBAL_SCRIPT,
            error=error,
            pending=False,
            view="register",
        )

    connection = db()

    existing = connection.execute(
        """
        SELECT id
        FROM users
        WHERE email = ?
        """,
        (
            email,
        ),
    ).fetchone()

    if existing:

        connection.close()

        return render_template_string(
            LOGIN_HTML,
            style=PAGE_STYLE,
            global_script=GLOBAL_SCRIPT,
            error="Este e-mail já possui uma conta.",
            pending=False,
            view="register",
        )

    if phone and find_users_by_phone(
        connection,
        phone,
    ):

        connection.close()

        return render_template_string(
            LOGIN_HTML,
            style=PAGE_STYLE,
            global_script=GLOBAL_SCRIPT,
            error="Este telefone já possui uma conta.",
            pending=False,
            view="register",
        )

    connection.execute(
        """
        INSERT INTO users
        (
            username,
            email,
            phone,
            password_hash,
            approved,
            is_admin,
            created_at
        )
        VALUES (?, ?, ?, ?, 0, 0, ?)
        """,
        (
            username,
            email,
            phone,
            hash_password(
                password
            ),
            datetime.now().isoformat(
                timespec="seconds"
            ),
        ),
    )

    connection.commit()
    connection.close()

    return render_template_string(
        LOGIN_HTML,
        style=PAGE_STYLE,
        global_script=GLOBAL_SCRIPT,
        error=None,
        pending=True,
    )


# ============================================================
# RECUPERAÇÃO DE SENHA POR CÓDIGO DE VERIFICAÇÃO
# ============================================================

def reset_json(
    ok,
    text,
    status=200,
    restart=False,
):

    payload = {
        "ok": ok,
        ("message" if ok else "error"): text,
    }

    if restart:
        payload["restart"] = True

    return jsonify(payload), status


@app.route(
    "/forgot-password",
    methods=["POST"],
)
def forgot_password():

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        data = {}

    identifier = str(
        data.get(
            "identifier",
            "",
        )
    ).strip()[:160]

    session.pop(
        "password_reset",
        None,
    )

    if not identifier:

        return reset_json(
            False,
            "Informe o e-mail ou telefone cadastrado.",
            400,
        )

    if not smtp_configured():

        return reset_json(
            False,
            (
                "O serviço de envio do código de verificação "
                "ainda não está configurado. O administrador precisa "
                "configurar o envio de e-mail (LUCRA_SMTP_HOST, "
                "LUCRA_SMTP_PORT, LUCRA_SMTP_USER, LUCRA_SMTP_PASSWORD "
                "e LUCRA_SMTP_FROM). Nenhum código foi enviado."
            ),
            503,
        )

    generic_message = (
        "Se os dados informados pertencerem a uma conta, "
        "um código de verificação foi enviado para o e-mail "
        f"cadastrado. Ele expira em {RESET_CODE_MINUTES} minutos."
    )

    session["password_reset"] = {
        "identifier": identifier,
    }

    connection = db()

    user = find_user_by_identifier(
        connection,
        identifier,
    )

    if not user or not user["email"]:

        connection.close()

        return reset_json(
            True,
            generic_message,
        )

    now = utc_now()

    existing = connection.execute(
        """
        SELECT *
        FROM password_resets
        WHERE user_id = ?
        """,
        (
            user["id"],
        ),
    ).fetchone()

    if existing and not int(existing["verified"]):

        try:
            created = datetime.fromisoformat(
                existing["created_at"]
            )
        except (TypeError, ValueError):
            created = now - timedelta(
                seconds=RESET_RESEND_SECONDS + 1
            )

        if (now - created).total_seconds() < RESET_RESEND_SECONDS:

            connection.close()

            return reset_json(
                True,
                generic_message,
            )

    code = str(
        secrets.randbelow(900000)
        + 100000
    )

    connection.execute(
        """
        DELETE FROM password_resets
        WHERE user_id = ?
        """,
        (
            user["id"],
        ),
    )

    connection.execute(
        """
        INSERT INTO password_resets
        (
            user_id,
            code_hash,
            channel,
            attempts,
            expires_at,
            created_at,
            verified,
            grant_hash
        )
        VALUES (?, ?, 'email', 0, ?, ?, 0, '')
        """,
        (
            user["id"],
            hash_password(
                code
            ),
            (
                now
                + timedelta(
                    minutes=RESET_CODE_MINUTES
                )
            ).isoformat(),
            now.isoformat(),
        ),
    )

    connection.commit()

    try:

        send_email(
            user["email"],
            "LUCRA.AI — Código de verificação",
            (
                f"Olá, {user['username']}.\n\n"
                "Recebemos uma solicitação para redefinir a senha "
                "da sua conta LUCRA.AI.\n\n"
                f"Seu código de verificação é: {code}\n\n"
                f"O código expira em {RESET_CODE_MINUTES} minutos, "
                f"permite até {RESET_MAX_ATTEMPTS} tentativas e só "
                "pode ser usado uma vez.\n\n"
                "Se você não fez esta solicitação, ignore este e-mail. "
                "Sua senha atual continua válida.\n\n"
                "LUCRA.AI — Executive Vision"
            ),
        )

    except Exception:

        connection.execute(
            """
            DELETE FROM password_resets
            WHERE user_id = ?
            """,
            (
                user["id"],
            ),
        )

        connection.commit()
        connection.close()

        app.logger.exception(
            "Falha ao enviar código de verificação."
        )

        return reset_json(
            False,
            (
                "Não foi possível enviar o código de verificação agora. "
                "Verifique a configuração de e-mail do servidor e tente novamente."
            ),
            502,
        )

    connection.close()

    return reset_json(
        True,
        generic_message,
    )


@app.route(
    "/forgot-password/verify",
    methods=["POST"],
)
def forgot_password_verify():

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        data = {}

    state = session.get(
        "password_reset"
    ) or {}

    identifier = state.get(
        "identifier"
    )

    code = normalize_phone(
        data.get(
            "code",
            "",
        )
    )

    if not identifier:

        return reset_json(
            False,
            "Solicite um novo código de verificação.",
            400,
            restart=True,
        )

    if len(code) != 6:

        return reset_json(
            False,
            "Digite o código de 6 dígitos.",
            400,
        )

    connection = db()

    user = find_user_by_identifier(
        connection,
        identifier,
    )

    row = None

    if user:

        row = connection.execute(
            """
            SELECT *
            FROM password_resets
            WHERE user_id = ?
            AND verified = 0
            """,
            (
                user["id"],
            ),
        ).fetchone()

    if not user or not row:

        connection.close()

        return reset_json(
            False,
            "Código inválido ou expirado. Solicite um novo código.",
            400,
        )

    now = utc_now()

    try:
        expires = datetime.fromisoformat(
            row["expires_at"]
        )
    except (TypeError, ValueError):
        expires = now

    if now >= expires:

        connection.execute(
            "DELETE FROM password_resets WHERE id = ?",
            (
                row["id"],
            ),
        )

        connection.commit()
        connection.close()

        session.pop(
            "password_reset",
            None,
        )

        return reset_json(
            False,
            "O código expirou. Solicite um novo código.",
            400,
            restart=True,
        )

    if int(row["attempts"]) >= RESET_MAX_ATTEMPTS:

        connection.execute(
            "DELETE FROM password_resets WHERE id = ?",
            (
                row["id"],
            ),
        )

        connection.commit()
        connection.close()

        session.pop(
            "password_reset",
            None,
        )

        return reset_json(
            False,
            "Limite de tentativas atingido. Solicite um novo código.",
            429,
            restart=True,
        )

    if not verify_password(
        code,
        row["code_hash"],
    ):

        attempts = int(row["attempts"]) + 1

        if attempts >= RESET_MAX_ATTEMPTS:

            connection.execute(
                "DELETE FROM password_resets WHERE id = ?",
                (
                    row["id"],
                ),
            )

            connection.commit()
            connection.close()

            session.pop(
                "password_reset",
                None,
            )

            return reset_json(
                False,
                "Limite de tentativas atingido. O código foi bloqueado. Solicite um novo código.",
                429,
                restart=True,
            )

        connection.execute(
            """
            UPDATE password_resets
            SET attempts = ?
            WHERE id = ?
            """,
            (
                attempts,
                row["id"],
            ),
        )

        connection.commit()
        connection.close()

        return reset_json(
            False,
            (
                "Código incorreto. Tentativas restantes: "
                f"{RESET_MAX_ATTEMPTS - attempts}."
            ),
            400,
        )

    grant = secrets.token_urlsafe(
        32
    )

    connection.execute(
        """
        UPDATE password_resets
        SET
            verified = 1,
            code_hash = '',
            grant_hash = ?,
            expires_at = ?
        WHERE id = ?
        """,
        (
            grant_digest(
                grant
            ),
            (
                now
                + timedelta(
                    minutes=RESET_GRANT_MINUTES
                )
            ).isoformat(),
            row["id"],
        ),
    )

    connection.commit()
    connection.close()

    session["password_reset"] = {
        "identifier": identifier,
        "grant": grant,
    }

    return reset_json(
        True,
        "Código validado. Defina sua nova senha.",
    )


@app.route(
    "/forgot-password/reset",
    methods=["POST"],
)
def forgot_password_reset():

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        data = {}

    state = session.get(
        "password_reset"
    ) or {}

    identifier = state.get(
        "identifier"
    )

    grant = state.get(
        "grant"
    )

    password = str(
        data.get(
            "password",
            "",
        )
    )

    password_confirm = str(
        data.get(
            "password_confirm",
            "",
        )
    )

    if not identifier or not grant:

        return reset_json(
            False,
            "Valide o código de verificação antes de trocar a senha.",
            400,
            restart=True,
        )

    if len(password) < 6:

        return reset_json(
            False,
            "A nova senha precisa ter pelo menos 6 caracteres.",
            400,
        )

    if len(password) > 120:

        return reset_json(
            False,
            "A nova senha pode ter no máximo 120 caracteres.",
            400,
        )

    if password != password_confirm:

        return reset_json(
            False,
            "As senhas não são iguais.",
            400,
        )

    connection = db()

    user = find_user_by_identifier(
        connection,
        identifier,
    )

    row = None

    if user:

        row = connection.execute(
            """
            SELECT *
            FROM password_resets
            WHERE user_id = ?
            AND verified = 1
            """,
            (
                user["id"],
            ),
        ).fetchone()

    valid = bool(
        user
        and row
        and row["grant_hash"]
        and secrets.compare_digest(
            row["grant_hash"],
            grant_digest(
                grant
            ),
        )
    )

    if valid:

        try:
            valid = utc_now() < datetime.fromisoformat(
                row["expires_at"]
            )
        except (TypeError, ValueError):
            valid = False

    if not valid:

        if user:

            connection.execute(
                "DELETE FROM password_resets WHERE user_id = ?",
                (
                    user["id"],
                ),
            )

            connection.commit()

        connection.close()

        session.pop(
            "password_reset",
            None,
        )

        return reset_json(
            False,
            "A validação expirou. Solicite um novo código.",
            400,
            restart=True,
        )

    connection.execute(
        """
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
        """,
        (
            hash_password(
                password
            ),
            user["id"],
        ),
    )

    connection.execute(
        "DELETE FROM password_resets WHERE user_id = ?",
        (
            user["id"],
        ),
    )

    connection.commit()
    connection.close()

    session.pop(
        "password_reset",
        None,
    )

    return reset_json(
        True,
        "Senha alterada com sucesso. Entre com a nova senha.",
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route(
    "/dashboard",
    methods=["GET"],
)
@login_required
def dashboard():

    user = current_user()

    metrics = aggregate_user_metrics(
        user["id"]
    )

    sources = source_summary(
        user["id"]
    )

    return render_template_string(
        DASHBOARD_HTML,
        style=PAGE_STYLE,
        global_script=GLOBAL_SCRIPT,
        user=user,
        metrics=metrics,
        sources=sources,
        company_sheet=next(
            (
                source
                for source in sources
                if source["source_type"] == "empresa"
            ),
            None,
        ),
        sheet_accept=SHEET_ACCEPT,
    )


# ============================================================
# UPLOAD DE ARQUIVO
# ============================================================

@app.route(
    "/upload",
    methods=["POST"],
)
@login_required
def upload():

    user = current_user()

    uploaded_file = request.files.get(
        "file"
    )

    if not uploaded_file:

        return jsonify(
            {
                "ok": False,
                "error": "Nenhum arquivo foi enviado.",
            }
        ), 400

    relative_name = request.form.get(
        "relative_path"
    )

    source_type = request.form.get(
        "source_type",
        "file",
    )

    if source_type not in {
        "file",
        "folder",
        "empresa",
    }:
        source_type = "file"

    if source_type == "empresa":

        connection = db()

        existing_sheet = connection.execute(
            """
            SELECT id
            FROM datasets
            WHERE user_id = ?
            AND source_type = 'empresa'
            LIMIT 1
            """,
            (
                user["id"],
            ),
        ).fetchone()

        connection.close()

        if existing_sheet:

            return jsonify(
                {
                    "ok": False,
                    "error": (
                        "Já existe uma planilha da empresa fixada. "
                        "Exclua pela lixeira 🗑️ para adicionar outra."
                    ),
                }
            ), 409

    try:

        result = save_and_ingest(
            user["id"],
            uploaded_file,
            source_type=source_type,
            relative_name=relative_name,
        )

        return jsonify(
            {
                "ok": True,
                "message": "Arquivo incorporado com sucesso.",
                "result": result,
            }
        )

    except Exception as exc:

        return jsonify(
            {
                "ok": False,
                "error": str(exc),
            }
        ), 400


# ============================================================
# INCORPORAR PASTA PELO CAMINHO DO SERVIDOR
# ============================================================

@app.route(
    "/api/incorporate-folder",
    methods=["POST"],
)
@login_required
def incorporate_folder():

    user = current_user()

    data = request.get_json(
        silent=True
    ) or {}

    folder = str(
        data.get(
            "folder",
            "",
        )
    ).strip()

    if not folder:

        return jsonify(
            {
                "ok": False,
                "error": "Informe a pasta.",
            }
        ), 400

    requested = Path(
        folder
    ).expanduser()

    try:

        requested = requested.resolve()

    except Exception:

        return jsonify(
            {
                "ok": False,
                "error": "Pasta inválida.",
            }
        ), 400

    if not requested.exists():

        return jsonify(
            {
                "ok": False,
                "error": "A pasta não existe.",
            }
        ), 404

    if not requested.is_dir():

        return jsonify(
            {
                "ok": False,
                "error": "O caminho informado não é uma pasta.",
            }
        ), 400

    count = 0
    errors = []

    user_folder = (
        UPLOAD_FOLDER
        / str(user["id"])
        / "pastas"
        / secure_filename(
            requested.name
        )
    )

    user_folder.mkdir(
        parents=True,
        exist_ok=True,
    )

    for source_file in requested.rglob("*"):

        if not source_file.is_file():
            continue

        if (
            source_file.suffix.lower()
            not in {
                ".csv",
                ".xls",
                ".xlsx",
            }
        ):
            continue

        try:

            relative = source_file.relative_to(
                requested
            )

            destination = (
                user_folder
                / secure_relative_path(
                    relative.as_posix()
                )
            )

            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            destination.write_bytes(
                source_file.read_bytes()
            )

            dataframe = read_dataframe(
                destination
            )

            dataframe.columns = [
                str(c).strip()
                for c in dataframe.columns
            ]

            analysis = analyze_dataframe(
                dataframe
            )

            connection = db()

            connection.execute(
                """
                INSERT INTO datasets
                (
                    user_id,
                    filename,
                    created_at,
                    data_json,
                    filepath,
                    relative_path,
                    source_type,
                    row_count,
                    columns_json,
                    analysis_json,
                    sha256
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user["id"],
                    source_file.name,
                    datetime.now().isoformat(
                        timespec="seconds"
                    ),
                    "{}",
                    str(destination),
                    (
                        Path(
                            "pastas"
                        )
                        / secure_filename(
                            requested.name
                        )
                        / secure_relative_path(
                            relative.as_posix()
                        )
                    ).as_posix(),
                    "folder",
                    analysis["rows"],
                    json.dumps(
                        analysis[
                            "columns"
                        ],
                        ensure_ascii=False,
                    ),
                    json.dumps(
                        analysis,
                        ensure_ascii=False,
                    ),
                    file_sha256(
                        destination
                    ),
                ),
            )

            connection.commit()
            connection.close()

            count += 1

        except Exception as exc:

            errors.append(
                f"{source_file.name}: {exc}"
            )

    connection = db()

    connection.execute(
        """
        INSERT OR IGNORE INTO source_roots
        (
            user_id,
            root_name,
            created_at
        )
        VALUES (?, ?, ?)
        """,
        (
            user["id"],
            requested.name,
            datetime.now().isoformat(
                timespec="seconds"
            ),
        ),
    )

    connection.commit()
    connection.close()

    return jsonify(
        {
            "ok": True,
            "files": count,
            "errors": errors[:20],
        }
    )


# ============================================================
# CHAT
# ============================================================

@app.route(
    "/api/chat",
    methods=["POST"],
)
@login_required
def api_chat():

    user = current_user()

    data = request.get_json(
        silent=True
    ) or {}

    message = str(
        data.get(
            "message",
            "",
        )
    ).strip()

    if not message:

        return jsonify(
            {
                "ok": False,
                "error": "Digite uma pergunta.",
            }
        ), 400

    if len(message) > 5000:

        return jsonify(
            {
                "ok": False,
                "error": "A pergunta é muito longa.",
            }
        ), 400

    try:
        conversation_id = int(
            data.get("conversation_id") or 0
        ) or None
    except (TypeError, ValueError):
        conversation_id = None

    try:

        answer = build_chat_answer(
            user,
            message,
        )

    except Exception:

        fallback = (
            "😬 Não consegui concluir a análise dos dados agora. "
            "Verifique se a planilha enviada está válida e tente novamente."
        )

        answer = {
            "summary": fallback,
            "detailed": fallback,
            "modes": False,
        }

    detailed = apply_emoji_level(
        answer["detailed"],
        data.get(
            "emoji_level",
            0,
        ),
    )

    has_modes = bool(
        answer.get("modes")
    )

    summary = (
        answer["summary"]
        if has_modes
        else detailed
    )

    now = datetime.now().isoformat(
        timespec="seconds"
    )

    connection = db()

    conversation = None

    if conversation_id:

        conversation = connection.execute(
            """
            SELECT *
            FROM conversations
            WHERE id = ?
            AND user_id = ?
            """,
            (
                conversation_id,
                user["id"],
            ),
        ).fetchone()

    if conversation:

        conversation_id = conversation["id"]
        title = conversation["title"]

        connection.execute(
            """
            UPDATE conversations
            SET updated_at = ?
            WHERE id = ?
            """,
            (
                now,
                conversation_id,
            ),
        )

    else:

        title = conversation_title(message)

        cursor = connection.execute(
            """
            INSERT INTO conversations
            (
                user_id,
                title,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                user["id"],
                title,
                now,
                now,
            ),
        )

        conversation_id = cursor.lastrowid

    connection.execute(
        """
        INSERT INTO chat_history
        (
            user_id,
            message,
            response,
            response_summary,
            conversation_id,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user["id"],
            message,
            detailed,
            summary if has_modes else "",
            conversation_id,
            now,
        ),
    )

    connection.commit()
    connection.close()

    return jsonify(
        {
            "ok": True,
            "response": detailed,
            "detailed": detailed,
            "summary": summary,
            "has_modes": has_modes,
            "conversation_id": conversation_id,
            "conversation_title": title,
        }
    )


# ============================================================
# CONVERSAS SALVAS
# ============================================================

@app.route(
    "/api/conversations",
    methods=["GET"],
)
@login_required
def list_conversations():

    user = current_user()

    connection = db()

    rows = connection.execute(
        """
        SELECT id, title, updated_at
        FROM conversations
        WHERE user_id = ?
        ORDER BY updated_at DESC, id DESC
        LIMIT 100
        """,
        (
            user["id"],
        ),
    ).fetchall()

    connection.close()

    return jsonify(
        {
            "ok": True,
            "conversations": [
                {
                    "id": row["id"],
                    "title": row["title"],
                    "updated_at": row["updated_at"],
                }
                for row in rows
            ],
        }
    )


@app.route(
    "/api/conversations/<int:conversation_id>",
    methods=["GET", "DELETE"],
)
@login_required
def conversation_detail(
    conversation_id
):

    user = current_user()

    connection = db()

    conversation = connection.execute(
        """
        SELECT *
        FROM conversations
        WHERE id = ?
        AND user_id = ?
        """,
        (
            conversation_id,
            user["id"],
        ),
    ).fetchone()

    if not conversation:

        connection.close()

        return jsonify(
            {
                "ok": False,
                "error": "Conversa não encontrada.",
            }
        ), 404

    if request.method == "DELETE":

        connection.execute(
            """
            DELETE FROM chat_history
            WHERE conversation_id = ?
            AND user_id = ?
            """,
            (
                conversation_id,
                user["id"],
            ),
        )

        connection.execute(
            """
            DELETE FROM conversations
            WHERE id = ?
            AND user_id = ?
            """,
            (
                conversation_id,
                user["id"],
            ),
        )

        connection.commit()
        connection.close()

        return jsonify(
            {
                "ok": True,
            }
        )

    rows = connection.execute(
        """
        SELECT message, response, response_summary
        FROM chat_history
        WHERE conversation_id = ?
        AND user_id = ?
        ORDER BY id
        """,
        (
            conversation_id,
            user["id"],
        ),
    ).fetchall()

    connection.close()

    return jsonify(
        {
            "ok": True,
            "id": conversation["id"],
            "title": conversation["title"],
            "messages": [
                {
                    "message": row["message"],
                    "response": row["response"],
                    "summary": row["response_summary"] or "",
                }
                for row in rows
            ],
        }
    )


@app.route(
    "/api/session-status",
    methods=["GET"],
)
def session_status():

    user = current_user()

    if user and int(user["approved"]):

        return jsonify(
            {
                "ok": True,
            }
        )

    removed = bool(
        session.get("user_id")
    )

    session.clear()

    return jsonify(
        {
            "ok": False,
            "kicked": removed,
            "error": KICKED_MESSAGE,
        }
    ), 401


# ============================================================
# EXCLUIR FONTE
# ============================================================


@app.route(
    "/api/source/<int:source_id>",
    methods=["DELETE"],
)
@login_required
def delete_source(
    source_id
):

    user = current_user()

    connection = db()

    row = connection.execute(
        """
        SELECT *
        FROM datasets
        WHERE id = ?
        AND user_id = ?
        """,
        (
            source_id,
            user["id"],
        ),
    ).fetchone()

    if not row:

        connection.close()

        return jsonify(
            {
                "ok": False,
                "error": "Fonte não encontrada.",
            }
        ), 404

    filepath = row[
        "filepath"
    ]

    connection.execute(
        """
        DELETE FROM datasets
        WHERE id = ?
        AND user_id = ?
        """,
        (
            source_id,
            user["id"],
        ),
    )

    connection.commit()
    connection.close()

    if filepath:

        try:

            path = Path(
                filepath
            )

            if path.exists():

                path.unlink()

        except Exception:

            pass

    return jsonify(
        {
            "ok": True,
        }
    )


# ============================================================
# EXPORTAR EXCEL
# ============================================================

@app.route(
    "/export",
    methods=["GET"],
)
@login_required
def export_excel():

    user = current_user()

    sources = source_summary(
        user["id"]
    )

    metrics = aggregate_user_metrics(
        user["id"]
    )

    output = io.BytesIO()

    with pd.ExcelWriter(
        output,
        engine="openpyxl",
    ) as writer:

        metrics_df = pd.DataFrame(
            [
                {
                    "Indicador": key,
                    "Valor": value,
                }
                for key, value in metrics.items()
            ]
        )

        metrics_df.to_excel(
            writer,
            index=False,
            sheet_name="Visao_Geral",
        )

        source_df = pd.DataFrame(
            [
                {
                    "Arquivo": item[
                        "relative_path"
                    ],
                    "Fonte": item[
                        "source_type"
                    ],
                    "Linhas": item[
                        "rows"
                    ],
                    "Criado em": item[
                        "created_at"
                    ],
                }
                for item in sources
            ]
        )

        source_df.to_excel(
            writer,
            index=False,
            sheet_name="Fontes",
        )

        for item in sources[:30]:

            filepath = item.get(
                "filepath"
            )

            if not filepath:
                continue

            path = Path(
                filepath
            )

            if not path.exists():
                continue

            try:

                dataframe = read_dataframe(
                    path
                )

                sheet = re.sub(
                    r"[^A-Za-z0-9_]",
                    "_",
                    Path(
                        item[
                            "relative_path"
                        ]
                    ).stem,
                )[:31]

                if not sheet:
                    sheet = "Dados"

                dataframe.to_excel(
                    writer,
                    index=False,
                    sheet_name=sheet,
                )

            except Exception:

                continue

    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name=(
            "LUCRA_AI_Exportacao.xlsx"
        ),
        mimetype=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        ),
    )


# ============================================================
# ADMIN
# ============================================================

@app.route(
    "/admin",
    methods=["GET"],
)
@admin_required
def admin_page():

    connection = db()

    pending_users = connection.execute(
        """
        SELECT *
        FROM users
        WHERE approved = 0
        AND is_admin = 0
        AND COALESCE(revoked, 0) = 0
        ORDER BY id DESC
        """
    ).fetchall()

    accepted_users = connection.execute(
        """
        SELECT *
        FROM users
        WHERE approved = 1
        AND is_admin = 0
        ORDER BY lower(username), id
        """
    ).fetchall()

    connection.close()

    active_tab = (
        "aceitos"
        if request.args.get("tab") == "aceitos"
        else "solicitacoes"
    )

    return render_template_string(
        ADMIN_HTML,
        style=PAGE_STYLE,
        global_script=GLOBAL_SCRIPT,
        pending_users=pending_users,
        accepted_users=accepted_users,
        active_tab=active_tab,
    )


@app.route(
    "/admin/approve/<int:user_id>",
    methods=["POST"],
)
@admin_required
def approve_user(
    user_id
):

    connection = db()

    connection.execute(
        """
        UPDATE users
        SET approved = 1,
            revoked = 0
        WHERE id = ?
        AND is_admin = 0
        """,
        (
            user_id,
        ),
    )

    connection.commit()
    connection.close()

    return redirect(
        url_for(
            "admin_page"
        )
    )


@app.route(
    "/admin/revoke/<int:user_id>",
    methods=["POST"],
)
@admin_required
def revoke_user(
    user_id
):

    connection = db()

    connection.execute(
        """
        UPDATE users
        SET approved = 0,
            revoked = 1
        WHERE id = ?
        AND is_admin = 0
        """,
        (
            user_id,
        ),
    )

    connection.execute(
        """
        DELETE FROM password_resets
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    connection.commit()
    connection.close()

    return redirect(
        url_for(
            "admin_page",
            tab="aceitos",
        )
    )


@app.route(
    "/admin/delete/<int:user_id>",
    methods=["POST"],
)
@admin_required
def delete_user(
    user_id
):

    admin = current_user()

    if int(
        admin["id"]
    ) == int(
        user_id
    ):

        return (
            "O administrador principal não pode ser excluído.",
            400,
        )

    connection = db()

    datasets = connection.execute(
        """
        SELECT filepath
        FROM datasets
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    ).fetchall()

    connection.execute(
        """
        DELETE FROM conversations
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    connection.execute(
        """
        DELETE FROM chat_history
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    connection.execute(
        """
        DELETE FROM login_history
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    connection.execute(
        """
        DELETE FROM datasets
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    connection.execute(
        """
        DELETE FROM source_roots
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    connection.execute(
        """
        DELETE FROM password_resets
        WHERE user_id = ?
        """,
        (
            user_id,
        ),
    )

    connection.execute(
        """
        DELETE FROM users
        WHERE id = ?
        AND is_admin = 0
        """,
        (
            user_id,
        ),
    )

    connection.commit()
    connection.close()

    for item in datasets:

        filepath = item[
            "filepath"
        ]

        if filepath:

            try:

                Path(
                    filepath
                ).unlink(
                    missing_ok=True
                )

            except Exception:

                pass

    user_folder = (
        UPLOAD_FOLDER
        / str(user_id)
    )

    if user_folder.exists():

        import shutil

        try:

            shutil.rmtree(
                user_folder
            )

        except Exception:

            pass

    return redirect(
        url_for(
            "admin_page"
        )
    )


# ============================================================
# MANIFEST
# ============================================================

@app.route(
    "/manifest.json",
    methods=["GET"],
)
def manifest():

    return jsonify(
        {
            "name": "LUCRA.AI",
            "short_name": "LUCRA.AI",
            "description": (
                "LUCRA.AI — Executive Vision"
            ),
            "start_url": "/",
            "display": "standalone",
            "background_color": "#050505",
            "theme_color": "#D4AF37",
            "lang": "pt-BR",
            "icons": [
                {
                    "src": "/icon.png",
                    "sizes": "192x192",
                    "type": "image/png",
                    "purpose": "any maskable",
                },
                {
                    "src": "/icon.png",
                    "sizes": "512x512",
                    "type": "image/png",
                    "purpose": "any maskable",
                },
            ],
        }
    )


# ============================================================
# LOGO / ÍCONE
# ============================================================

@app.route(
    "/icon.png",
    methods=["GET"],
)
def icon():

    candidates = [
        BASE_DIR / "icon.png",
        STATIC_IMAGE_FOLDER / "icon.png",
        STATIC_IMAGE_FOLDER / "lucra-icon.png",
        STATIC_IMAGE_FOLDER / "lucra-icon.jpg",
        BASE_DIR / "lucra-icon.png",
        BASE_DIR / "lucra-icon.jpg",
    ]

    for candidate in candidates:

        if candidate.exists():

            mimetype = (
                "image/png"
                if candidate.suffix.lower()
                == ".png"
                else "image/jpeg"
            )

            return send_file(
                candidate,
                mimetype=mimetype,
                max_age=3600,
            )

    abort(
        404,
        description=(
            "Coloque o logo oficial como icon.png "
            "na pasta principal do projeto."
        ),
    )


@app.route(
    "/logo-dourada.png",
    methods=["GET"],
)
def logo_dourada():

    candidates = [
        BASE_DIR / "logo-dourada.png",
        STATIC_IMAGE_FOLDER / "logo-dourada.png",
        STATIC_IMAGE_FOLDER / "logo.png",
        BASE_DIR / "logo.png",
    ]

    for candidate in candidates:

        if candidate.exists():

            mimetype = (
                "image/png"
                if candidate.suffix.lower()
                == ".png"
                else "image/jpeg"
            )

            return send_file(
                candidate,
                mimetype=mimetype,
                max_age=3600,
            )

    abort(
        404,
        description=(
            "Coloque o logo oficial como "
            "logo-dourada.png na pasta principal."
        ),
    )


# ============================================================
# DOWNLOAD ANDROID
# ============================================================

@app.route(
    "/download/android",
    methods=["GET"],
)
def download_android():

    file = (
        DOWNLOAD_FOLDER
        / "android"
        / "LUCRA_AI.apk"
    )

    if not file.exists():

        abort(
            404,
            description=(
                "APK ainda não publicado."
            ),
        )

    return send_from_directory(
        str(file.parent),
        file.name,
        as_attachment=True,
        download_name="LUCRA_AI.apk",
    )


# ============================================================
# DOWNLOAD WINDOWS
# ============================================================

@app.route(
    "/download/windows",
    methods=["GET"],
)
def download_windows():

    file = (
        DOWNLOAD_FOLDER
        / "windows"
        / "LUCRA_AI_Setup.exe"
    )

    if not file.exists():

        abort(
            404,
            description=(
                "EXE ainda não publicado."
            ),
        )

    return send_from_directory(
        str(file.parent),
        file.name,
        as_attachment=True,
        download_name="LUCRA_AI_Setup.exe",
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/logout",
    methods=["GET"],
)
def logout():

    session.clear()

    return redirect(
        url_for(
            "login_page"
        )
    )


# ============================================================
# SEGURANÇA / CACHE
# ============================================================

@app.after_request
def security_headers(
    response
):

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "SAMEORIGIN"

    response.headers[
        "Referrer-Policy"
    ] = (
        "strict-origin-when-cross-origin"
    )

    response.headers[
        "Permissions-Policy"
    ] = (
        "camera=(), "
        "microphone=(), "
        "geolocation=()"
    )

    private_paths = (
        "/login",
        "/register",
        "/forgot-password",
        "/admin",
        "/dashboard",
        "/api/",
        "/upload",
        "/export",
    )

    if request.path.startswith(
        private_paths
    ):

        response.headers[
            "Cache-Control"
        ] = "no-store"

    response.headers[
        "Content-Security-Policy"
    ] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'self'"
    )

    response.headers[
        "Cross-Origin-Opener-Policy"
    ] = "same-origin"

    response.headers[
        "Cross-Origin-Resource-Policy"
    ] = "same-origin"

    response.headers[
        "X-Permitted-Cross-Domain-Policies"
    ] = "none"

    if app.config.get(
        "SESSION_COOKIE_SECURE"
    ):
        response.headers[
            "Strict-Transport-Security"
        ] = "max-age=31536000; includeSubDomains"

    response.headers[
        "Server"
    ] = "LUCRA.AI"

    return response


# ============================================================
# ERROS
# ============================================================

@app.errorhandler(
    413
)
def request_too_large(
    error
):

    if request.path.startswith(
        "/api/"
    ) or request.path == "/upload":

        return jsonify(
            {
                "ok": False,
                "error": (
                    "O arquivo ou solicitação "
                    "ultrapassou o limite permitido."
                ),
            }
        ), 413

    return (
        "Arquivo ou solicitação muito grande.",
        413,
    )


@app.errorhandler(
    404
)
def not_found(
    error
):

    if request.path.startswith(
        "/api/"
    ):

        return jsonify(
            {
                "ok": False,
                "error": "Recurso não encontrado.",
            }
        ), 404

    return (
        "Página não encontrada.",
        404,
    )


@app.errorhandler(
    500
)
def internal_error(
    error
):

    if request.path.startswith(
        "/api/"
    ):

        return jsonify(
            {
                "ok": False,
                "error": (
                    "Erro interno. "
                    "Tente novamente."
                ),
            }
        ), 500

    return (
        "Erro interno da LUCRA.AI.",
        500,
    )


# ============================================================
# INICIAR
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "8000",
        )
    )

    print(
        "=========================================="
    )

    print(
        "       LUCRA.AI — EXECUTIVE VISION"
    )

    print(
        "=========================================="
    )

    print(
        f"Site local: http://127.0.0.1:{port}/"
    )

    print(
        f"Banco:      {DATABASE}"
    )

    print(
        f"Uploads:    {UPLOAD_FOLDER}"
    )

    print(
        f"Admin:      {ADMIN_EMAIL}"
    )

    print(
        "=========================================="
    )

    from werkzeug.serving import WSGIRequestHandler

    WSGIRequestHandler.server_version = "LUCRA.AI"

    WSGIRequestHandler.sys_version = ""

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
    )