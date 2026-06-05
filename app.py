import os
import re
import secrets
import sqlite3
import json
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, Response, render_template, request, redirect, url_for, jsonify, g, session
from cryptography.fernet import Fernet
import pymysql

DATA_DIR = os.environ.get("MGM_DATA_DIR", "/var/lib/mysql-grant-manager")
DB_PATH = os.path.join(DATA_DIR, "app.db")
KEY_PATH = os.path.join(DATA_DIR, ".encryption_key")
SECRET_KEY_PATH = os.path.join(DATA_DIR, ".secret_key")

app = Flask(__name__)

if os.path.exists(SECRET_KEY_PATH):
    with open(SECRET_KEY_PATH, "rb") as f:
        app.secret_key = f.read()
else:
    app.secret_key = os.urandom(32)
    with open(SECRET_KEY_PATH, "wb") as f:
        f.write(app.secret_key)


@app.template_filter("from_json")
def from_json_filter(value):
    if not value:
        return []
    return json.loads(value)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def get_cipher():
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_PATH, "wb") as f:
            f.write(key)
    return Fernet(key)


def encrypt(value):
    return get_cipher().encrypt(value.encode()).decode()


def decrypt(value):
    return get_cipher().decrypt(value.encode()).decode()


def _escape_mysql_string(value):
    return pymysql.converters.escape_string(str(value))


def _validate_mysql_user_or_host(value):
    v = str(value)
    if not re.match(r"^[a-zA-Z0-9_\-\.\%]+$", v):
        raise ValueError(f"Invalid MySQL user/host: {value}")
    return v


def _safe_identifier(value):
    return "`" + str(value).replace("`", "``") + "`"


# Privilégios de nível de database/tabela aceitos em `GRANT <priv> ON db.*`.
# Fonte: https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html
_ALLOWED_PRIVILEGES = {
    "ALL", "ALL PRIVILEGES",
    "ALTER", "ALTER ROUTINE",
    "CREATE", "CREATE ROUTINE", "CREATE TEMPORARY TABLES",
    "CREATE VIEW", "DELETE", "DROP", "EVENT", "EXECUTE",
    "GRANT OPTION", "INDEX", "INSERT", "LOCK TABLES",
    "REFERENCES", "SELECT", "SHOW VIEW", "TRIGGER", "UPDATE",
}


def _validate_privileges(value):
    """Valida uma lista de privilégios (separados por vírgula) contra a whitelist.

    Retorna a string normalizada (UPPER, sem espaços extras) pronta para ser
    interpolada no GRANT. Levanta ValueError em qualquer item desconhecido,
    impedindo SQL injection via o campo de privilégios.
    """
    raw = str(value).strip()
    if not raw:
        raise ValueError("Nenhum privilégio informado.")

    parts = [p.strip().upper() for p in raw.split(",") if p.strip()]
    if not parts:
        raise ValueError("Nenhum privilégio informado.")

    validated = []
    for p in parts:
        # colapsa espaços internos (ex.: "ALL   PRIVILEGES" -> "ALL PRIVILEGES")
        normalized = " ".join(p.split())
        if normalized not in _ALLOWED_PRIVILEGES:
            raise ValueError(f"Privilégio inválido ou não permitido: {p}")
        validated.append(normalized)

    return ", ".join(validated)


def check_auth(username, password):
    mgm_user = os.environ.get("MGM_USER", "admin")
    mgm_pass = os.environ.get("MGM_PASS", "admin")
    return secrets.compare_digest(username, mgm_user) and secrets.compare_digest(password, mgm_pass)


def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return Response("Access Denied", 401, {"WWW-Authenticate": 'Basic realm="MySQL Grant Manager"'})
        return f(*args, **kwargs)
    return decorated


def _generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.context_processor
def csrf_context():
    return {"csrf_token": _generate_csrf_token()}


def csrf_protect(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            expected = session.get("csrf_token")
            if not expected:
                return jsonify({"ok": False, "error": "CSRF token missing from session"}), 403
            sent = request.headers.get("X-CSRF-Token", "") or request.form.get("_csrf_token", "")
            if not sent or not secrets.compare_digest(expected, sent):
                return jsonify({"ok": False, "error": "CSRF token invalid"}), 403
        return f(*args, **kwargs)
    return decorated


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER DEFAULT 3306,
            admin_user TEXT NOT NULL,
            admin_password TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS server_databases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            database_name TEXT NOT NULL,
            refreshed_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
            UNIQUE(server_id, database_name)
        );

        CREATE TABLE IF NOT EXISTS grant_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            server_name TEXT NOT NULL,
            grantee_user TEXT NOT NULL,
            grantee_host TEXT NOT NULL,
            privileges TEXT NOT NULL DEFAULT '',
            databases TEXT NOT NULL DEFAULT '[]',
            grant_statement TEXT NOT NULL,
            executed_at TEXT NOT NULL DEFAULT (datetime('now')),
            success INTEGER NOT NULL DEFAULT 1,
            error_message TEXT,
            grant_type TEXT NOT NULL DEFAULT 'privilege',
            FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            role_name TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
            UNIQUE(server_id, role_name)
        );

        CREATE TABLE IF NOT EXISTS role_grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            role_name TEXT NOT NULL,
            grantee_user TEXT NOT NULL,
            grantee_host TEXT NOT NULL DEFAULT '%',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
        );
    """)
    try:
        db.execute("ALTER TABLE grant_history ADD COLUMN grant_type TEXT NOT NULL DEFAULT 'privilege'")
    except sqlite3.OperationalError:
        pass
    db.commit()
    db.close()


def mysql_connect(server):
    return pymysql.connect(
        host=server["host"],
        port=server["port"],
        user=server["admin_user"],
        password=decrypt(server["admin_password"]),
        charset="utf8mb4",
        connect_timeout=10,
        read_timeout=10,
        write_timeout=10,
    )


def discover_databases(server):
    conn = mysql_connect(server)
    try:
        with conn.cursor() as cur:
            cur.execute("SHOW DATABASES")
            databases = [row[0] for row in cur.fetchall()]
        return databases
    finally:
        conn.close()


def refresh_server_databases(server_id):
    db = get_db()
    server = db.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
    if not server:
        return None

    try:
        databases = discover_databases(dict(server))
    except Exception as e:
        raise e

    db.execute("DELETE FROM server_databases WHERE server_id = ?", (server_id,))
    now = datetime.now(timezone.utc).isoformat()
    for dbname in databases:
        db.execute(
            "INSERT INTO server_databases (server_id, database_name, refreshed_at) VALUES (?, ?, ?)",
            (server_id, dbname, now),
        )
    db.commit()
    return databases


def execute_grant(server, grantee_user, grantee_host, privileges, databases):
    user = _validate_mysql_user_or_host(grantee_user)
    host = _validate_mysql_user_or_host(grantee_host)
    priv = _validate_privileges(privileges)

    conn = mysql_connect(server)
    try:
        with conn.cursor() as cur:
            for dbname in databases:
                db = _safe_identifier(dbname)
                stmt = f"GRANT {priv} ON {db}.* TO '{user}'@'{host}'"
                cur.execute(stmt)
            cur.execute("FLUSH PRIVILEGES")
        conn.commit()
    finally:
        conn.close()


def _validate_role_name(value):
    v = str(value).strip()
    if not re.match(r"^[a-zA-Z0-9_\-\.\%]+$", v):
        raise ValueError(f"Invalid role name: {value}")
    return v


def mysql_create_role(server, role_name):
    role = _validate_role_name(role_name)
    conn = mysql_connect(server)
    try:
        with conn.cursor() as cur:
            cur.execute(f"CREATE ROLE IF NOT EXISTS '{role}'")
        conn.commit()
    finally:
        conn.close()


def mysql_drop_role(server, role_name):
    role = _validate_role_name(role_name)
    conn = mysql_connect(server)
    try:
        with conn.cursor() as cur:
            cur.execute(f"DROP ROLE IF EXISTS '{role}'")
        conn.commit()
    finally:
        conn.close()


def mysql_grant_role(server, role_name, user, host):
    role = _validate_role_name(role_name)
    u = _validate_mysql_user_or_host(user)
    h = _validate_mysql_user_or_host(host)
    conn = mysql_connect(server)
    try:
        with conn.cursor() as cur:
            cur.execute(f"GRANT '{role}' TO '{u}'@'{h}'")
        conn.commit()
    finally:
        conn.close()


def mysql_revoke_role(server, role_name, user, host):
    role = _validate_role_name(role_name)
    u = _validate_mysql_user_or_host(user)
    h = _validate_mysql_user_or_host(host)
    conn = mysql_connect(server)
    try:
        with conn.cursor() as cur:
            cur.execute(f"REVOKE '{role}' FROM '{u}'@'{h}'")
        conn.commit()
    finally:
        conn.close()


def mysql_set_default_role(server, user, host, role):
    u = _validate_mysql_user_or_host(user)
    h = _validate_mysql_user_or_host(host)
    role_val = str(role).strip()
    conn = mysql_connect(server)
    try:
        with conn.cursor() as cur:
            if role_val.upper() == "NONE":
                cur.execute(f"SET DEFAULT ROLE NONE TO '{u}'@'{h}'")
            elif role_val.upper() == "ALL":
                cur.execute(f"SET DEFAULT ROLE ALL TO '{u}'@'{h}'")
            else:
                r = _validate_role_name(role_val)
                cur.execute(f"SET DEFAULT ROLE '{r}' TO '{u}'@'{h}'")
        conn.commit()
    finally:
        conn.close()


def mysql_discover_roles(server):
    conn = mysql_connect(server)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT user FROM mysql.user WHERE account_locked = 'Y' AND host = '%' ORDER BY user")
            roles = [row[0] for row in cur.fetchall()]
        return roles
    finally:
        conn.close()


def mysql_discover_role_grants(server):
    conn = mysql_connect(server)
    try:
        with conn.cursor() as cur:
            try:
                cur.execute("SELECT FROM_USER as grantee_user, FROM_HOST as grantee_host, TO_USER as role_name FROM mysql.role_edges")
                grants = [dict(row) for row in cur.fetchall()]
            except Exception:
                grants = []
        return grants
    finally:
        conn.close()


def mysql_discover_users(server):
    conn = mysql_connect(server)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT CONCAT(user, '@', host) as user_host FROM mysql.user ORDER BY user, host")
            users = [row[0] for row in cur.fetchall()]
        return users
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
@auth_required
def index():
    db = get_db()
    server_count = db.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
    history_count = db.execute("SELECT COUNT(*) FROM grant_history").fetchone()[0]
    role_count = db.execute("SELECT COUNT(*) FROM roles").fetchone()[0]
    recent = db.execute(
        "SELECT * FROM grant_history ORDER BY executed_at DESC LIMIT 10"
    ).fetchall()
    return render_template(
        "index.html",
        server_count=server_count,
        history_count=history_count,
        role_count=role_count,
        recent=recent,
    )


@app.route("/servers")
@auth_required
def servers_list():
    db = get_db()
    servers = db.execute("SELECT * FROM servers ORDER BY name").fetchall()
    return render_template("servers.html", servers=servers)


@app.route("/servers/add", methods=["POST"])
@auth_required
@csrf_protect
def servers_add():
    name = request.form["name"].strip()
    host = request.form["host"].strip()
    port = int(request.form.get("port", 3306))
    admin_user = request.form["admin_user"].strip()
    admin_password = encrypt(request.form["admin_password"].strip())

    db = get_db()
    db.execute(
        "INSERT INTO servers (name, host, port, admin_user, admin_password) VALUES (?, ?, ?, ?, ?)",
        (name, host, port, admin_user, admin_password),
    )
    db.commit()
    return redirect(url_for("servers_list"))


@app.route("/servers/<int:server_id>/edit", methods=["POST"])
@auth_required
@csrf_protect
def servers_edit(server_id):
    db = get_db()
    data = {
        "name": request.form["name"].strip(),
        "host": request.form["host"].strip(),
        "port": int(request.form.get("port", 3306)),
        "admin_user": request.form["admin_user"].strip(),
    }
    if request.form["admin_password"].strip():
        data["admin_password"] = encrypt(request.form["admin_password"].strip())

    fields = ", ".join(f"{k} = ?" for k in data)
    values = list(data.values()) + [server_id]
    db.execute(f"UPDATE servers SET {fields} WHERE id = ?", values)
    db.commit()
    return redirect(url_for("servers_list"))


@app.route("/servers/<int:server_id>/delete", methods=["POST"])
@auth_required
@csrf_protect
def servers_delete(server_id):
    db = get_db()
    db.execute("DELETE FROM servers WHERE id = ?", (server_id,))
    db.commit()
    return redirect(url_for("servers_list"))


@app.route("/servers/<int:server_id>/test", methods=["POST"])
@auth_required
@csrf_protect
def servers_test(server_id):
    db = get_db()
    server = db.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
    if not server:
        return jsonify({"ok": False, "error": "Server not found"}), 404

    try:
        discover_databases(dict(server))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/servers/<int:server_id>/refresh", methods=["POST"])
@auth_required
@csrf_protect
def servers_refresh(server_id):
    try:
        databases = refresh_server_databases(server_id)
        if databases is None:
            return jsonify({"ok": False, "error": "Server not found"}), 404
        return jsonify({"ok": True, "databases": databases})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/servers/<int:server_id>/databases")
@auth_required
def servers_databases(server_id):
    db = get_db()
    rows = db.execute(
        "SELECT database_name FROM server_databases WHERE server_id = ? ORDER BY database_name",
        (server_id,),
    ).fetchall()
    return jsonify([r["database_name"] for r in rows])


@app.route("/servers/<int:server_id>/users")
@auth_required
def servers_users(server_id):
    db = get_db()
    server = db.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
    if not server:
        return jsonify({"ok": False, "error": "Server not found"}), 404
    try:
        users = mysql_discover_users(dict(server))
        return jsonify({"ok": True, "users": users})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/grants")
@auth_required
def grants_page():
    db = get_db()
    servers = db.execute("SELECT * FROM servers ORDER BY name").fetchall()
    return render_template("grants.html", servers=servers)


@app.route("/grants/create-user", methods=["POST"])
@auth_required
@csrf_protect
def grants_create_user():
    data = request.get_json()
    server_ids = data.get("server_ids", [])
    grantee_user = data.get("grantee_user", "").strip()
    grantee_host = data.get("grantee_host", "%").strip() or "%"
    password = data.get("password", "").strip()

    if not grantee_user or not server_ids:
        return jsonify({"ok": False, "error": "Preencha usuário e selecione servidores."})
    if not password:
        return jsonify({"ok": False, "error": "Senha do usuário é obrigatória."})

    db = get_db()
    results = []

    for sid in server_ids:
        sid = int(sid)
        server = db.execute("SELECT * FROM servers WHERE id = ?", (sid,)).fetchone()
        if not server:
            continue

        try:
            user = _validate_mysql_user_or_host(grantee_user)
            host = _validate_mysql_user_or_host(grantee_host)
            pwd = _escape_mysql_string(password)
            conn = mysql_connect(dict(server))
            try:
                with conn.cursor() as cur:
                    cur.execute(f"CREATE USER IF NOT EXISTS '{user}'@'{host}' IDENTIFIED BY '{pwd}'")
                    cur.execute("FLUSH PRIVILEGES")
                conn.commit()
            finally:
                conn.close()

            stmt = f"CREATE USER IF NOT EXISTS '{grantee_user}'@'{grantee_host}' IDENTIFIED BY '***'"
            db.execute(
                "INSERT INTO grant_history (server_id, server_name, grantee_user, grantee_host, privileges, databases, grant_statement, success) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                (sid, server["name"], grantee_user, grantee_host, "CREATE USER", "[]", stmt),
            )
            db.commit()
            results.append({"server_name": server["name"], "ok": True})
        except Exception as e:
            stmt = f"CREATE USER IF NOT EXISTS '{grantee_user}'@'{grantee_host}'"
            db.execute(
                "INSERT INTO grant_history (server_id, server_name, grantee_user, grantee_host, privileges, databases, grant_statement, success, error_message) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
                (sid, server["name"], grantee_user, grantee_host, "CREATE USER", "[]", stmt, str(e)),
            )
            db.commit()
            results.append({"server_name": server["name"], "ok": False, "error": str(e)})

    return jsonify({"ok": True, "results": results})


@app.route("/grants/preview", methods=["POST"])
@auth_required
@csrf_protect
def grants_preview():
    data = request.get_json()
    server_ids = data.get("server_ids", [])
    grantee_user = data.get("grantee_user", "").strip()
    grantee_host = data.get("grantee_host", "%").strip() or "%"
    privileges = data.get("privileges", "").strip()
    per_server_databases = data.get("databases", {})

    if not grantee_user or not privileges or not server_ids:
        return jsonify({"ok": False, "error": "Preencha usuário, privilégios e selecione servidores."})

    try:
        privileges = _validate_privileges(privileges)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)})

    db = get_db()
    preview = []
    for sid in server_ids:
        sid = int(sid)
        server = db.execute("SELECT * FROM servers WHERE id = ?", (sid,)).fetchone()
        if not server:
            continue

        dbs = per_server_databases.get(str(sid), [])
        if not dbs:
            available = db.execute(
                "SELECT database_name FROM server_databases WHERE server_id = ?",
                (sid,),
            ).fetchall()
            dbs = [r["database_name"] for r in available]

        statements = []
        for dbname in dbs:
            safe_db = _safe_identifier(dbname)
            stmt = f"GRANT {privileges} ON {safe_db}.* TO '{grantee_user}'@'{grantee_host}'"
            statements.append(stmt)

        preview.append(
            {
                "server_id": sid,
                "server_name": server["name"],
                "server_host": server["host"],
                "databases": dbs,
                "statements": statements,
            }
        )

    return jsonify({"ok": True, "preview": preview})


@app.route("/grants/execute", methods=["POST"])
@auth_required
@csrf_protect
def grants_execute():
    data = request.get_json()
    server_ids = data.get("server_ids", [])
    grantee_user = data.get("grantee_user", "").strip()
    grantee_host = data.get("grantee_host", "%").strip() or "%"
    privileges = data.get("privileges", "").strip()
    grantee_type = data.get("grantee_type", "user")
    per_server_databases = data.get("databases", {})

    if not grantee_user or not privileges or not server_ids:
        return jsonify({"ok": False, "error": "Preencha usuário, privilégios e selecione servidores."})

    db = get_db()
    results = []

    for sid in server_ids:
        sid = int(sid)
        server = db.execute("SELECT * FROM servers WHERE id = ?", (sid,)).fetchone()
        if not server:
            continue

        dbs = per_server_databases.get(str(sid), [])
        if not dbs:
            available = db.execute(
                "SELECT database_name FROM server_databases WHERE server_id = ?",
                (sid,),
            ).fetchall()
            dbs = [r["database_name"] for r in available]

        if not dbs:
            results.append(
                {
                    "server_name": server["name"],
                    "ok": False,
                    "error": "Nenhuma database disponível — execute Refresh primeiro.",
                }
            )
            continue

        try:
            execute_grant(dict(server), grantee_user, grantee_host, privileges, dbs)
            stmt = f"GRANT {privileges} ON {', '.join('`' + d + '`.*' for d in dbs)} TO '{grantee_user}'@'{grantee_host}'"
            db.execute(
                "INSERT INTO grant_history (server_id, server_name, grantee_user, grantee_host, privileges, databases, grant_statement, success) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                (
                    sid,
                    server["name"],
                    grantee_user,
                    grantee_host,
                    privileges,
                    json.dumps(dbs),
                    stmt,
                ),
            )
            db.commit()
            results.append({"server_name": server["name"], "ok": True})
        except Exception as e:
            stmt = f"GRANT {privileges} ON {', '.join('`' + d + '`.*' for d in dbs)} TO '{grantee_user}'@'{grantee_host}'"
            db.execute(
                "INSERT INTO grant_history (server_id, server_name, grantee_user, grantee_host, privileges, databases, grant_statement, success, error_message) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
                (
                    sid,
                    server["name"],
                    grantee_user,
                    grantee_host,
                    privileges,
                    json.dumps(dbs),
                    stmt,
                    str(e),
                ),
            )
            db.commit()
            results.append({"server_name": server["name"], "ok": False, "error": str(e)})

    return jsonify({"ok": True, "results": results})


@app.route("/history")
@auth_required
def history_page():
    db = get_db()
    history = db.execute(
        "SELECT * FROM grant_history ORDER BY executed_at DESC LIMIT 200"
    ).fetchall()
    return render_template("history.html", history=history)


@app.route("/history/<int:history_id>")
@auth_required
def history_detail(history_id):
    db = get_db()
    record = db.execute(
        "SELECT * FROM grant_history WHERE id = ?", (history_id,)
    ).fetchone()
    if not record:
        return "Not found", 404
    return jsonify(dict(record))


@app.route("/roles")
@auth_required
def roles_page():
    db = get_db()
    servers = db.execute("SELECT * FROM servers ORDER BY name").fetchall()
    return render_template("roles.html", servers=servers)


@app.route("/roles/<int:server_id>/sync", methods=["POST"])
@auth_required
@csrf_protect
def roles_sync(server_id):
    db = get_db()
    server = db.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
    if not server:
        return jsonify({"ok": False, "error": "Server not found"}), 404

    try:
        roles = mysql_discover_roles(dict(server))
        db.execute("DELETE FROM roles WHERE server_id = ?", (server_id,))
        for role in roles:
            db.execute(
                "INSERT OR IGNORE INTO roles (server_id, role_name) VALUES (?, ?)",
                (server_id, role),
            )

        grants = mysql_discover_role_grants(dict(server))
        db.execute("DELETE FROM role_grants WHERE server_id = ?", (server_id,))
        for g in grants:
            db.execute(
                "INSERT INTO role_grants (server_id, role_name, grantee_user, grantee_host) VALUES (?, ?, ?, ?)",
                (server_id, g["role_name"], g["grantee_user"], g["grantee_host"]),
            )

        db.commit()
        return jsonify({"ok": True, "roles": roles, "grants": [dict(g) for g in grants]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/roles/<int:server_id>")
@auth_required
def roles_for_server(server_id):
    db = get_db()
    local_roles = db.execute(
        "SELECT * FROM roles WHERE server_id = ? ORDER BY role_name", (server_id,)
    ).fetchall()
    local_grants = db.execute(
        "SELECT * FROM role_grants WHERE server_id = ? ORDER BY role_name, grantee_user, grantee_host",
        (server_id,),
    ).fetchall()
    return jsonify({
        "roles": [dict(r) for r in local_roles],
        "grants": [dict(g) for g in local_grants],
    })


@app.route("/roles/create", methods=["POST"])
@auth_required
@csrf_protect
def roles_create():
    data = request.get_json()
    server_ids = data.get("server_ids", [])
    role_name = data.get("role_name", "").strip()

    if not role_name or not server_ids:
        return jsonify({"ok": False, "error": "Preencha o nome da role e selecione servidores."})

    db = get_db()
    results = []

    for sid in server_ids:
        sid = int(sid)
        server = db.execute("SELECT * FROM servers WHERE id = ?", (sid,)).fetchone()
        if not server:
            continue

        try:
            mysql_create_role(dict(server), role_name)
            db.execute(
                "INSERT OR IGNORE INTO roles (server_id, role_name) VALUES (?, ?)",
                (sid, role_name),
            )
            stmt = f"CREATE ROLE IF NOT EXISTS '{role_name}'"
            db.execute(
                "INSERT INTO grant_history (server_id, server_name, grantee_user, grantee_host, privileges, databases, grant_statement, success, grant_type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'role')",
                (sid, server["name"], role_name, "%", "CREATE ROLE", "[]", stmt),
            )
            db.commit()
            results.append({"server_name": server["name"], "ok": True})
        except Exception as e:
            stmt = f"CREATE ROLE IF NOT EXISTS '{role_name}'"
            db.execute(
                "INSERT INTO grant_history (server_id, server_name, grantee_user, grantee_host, privileges, databases, grant_statement, success, error_message, grant_type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 'role')",
                (sid, server["name"], role_name, "%", "CREATE ROLE", "[]", stmt, str(e)),
            )
            db.commit()
            results.append({"server_name": server["name"], "ok": False, "error": str(e)})

    return jsonify({"ok": True, "results": results})


@app.route("/roles/grant", methods=["POST"])
@auth_required
@csrf_protect
def roles_grant():
    data = request.get_json()
    server_ids = data.get("server_ids", [])
    role_name = data.get("role_name", "").strip()
    grantee_user = data.get("grantee_user", "").strip()
    grantee_host = data.get("grantee_host", "%").strip() or "%"

    if not role_name or not grantee_user or not server_ids:
        return jsonify({"ok": False, "error": "Preencha role, usuário e selecione servidores."})

    db = get_db()
    results = []

    for sid in server_ids:
        sid = int(sid)
        server = db.execute("SELECT * FROM servers WHERE id = ?", (sid,)).fetchone()
        if not server:
            continue

        try:
            mysql_grant_role(dict(server), role_name, grantee_user, grantee_host)
            db.execute(
                "INSERT OR REPLACE INTO role_grants (server_id, role_name, grantee_user, grantee_host) VALUES (?, ?, ?, ?)",
                (sid, role_name, grantee_user, grantee_host),
            )
            stmt = f"GRANT '{role_name}' TO '{grantee_user}'@'{grantee_host}'"
            db.execute(
                "INSERT INTO grant_history (server_id, server_name, grantee_user, grantee_host, privileges, databases, grant_statement, success, grant_type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'role')",
                (sid, server["name"], grantee_user, grantee_host, role_name, "[]", stmt),
            )
            db.commit()
            results.append({"server_name": server["name"], "ok": True})
        except Exception as e:
            stmt = f"GRANT '{role_name}' TO '{grantee_user}'@'{grantee_host}'"
            db.execute(
                "INSERT INTO grant_history (server_id, server_name, grantee_user, grantee_host, privileges, databases, grant_statement, success, error_message, grant_type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 'role')",
                (sid, server["name"], grantee_user, grantee_host, role_name, "[]", stmt, str(e)),
            )
            db.commit()
            results.append({"server_name": server["name"], "ok": False, "error": str(e)})

    return jsonify({"ok": True, "results": results})


@app.route("/roles/revoke", methods=["POST"])
@auth_required
@csrf_protect
def roles_revoke():
    data = request.get_json()
    server_ids = data.get("server_ids", [])
    role_name = data.get("role_name", "").strip()
    grantee_user = data.get("grantee_user", "").strip()
    grantee_host = data.get("grantee_host", "%").strip() or "%"

    if not role_name or not grantee_user or not server_ids:
        return jsonify({"ok": False, "error": "Preencha role, usuário e selecione servidores."})

    db = get_db()
    results = []

    for sid in server_ids:
        sid = int(sid)
        server = db.execute("SELECT * FROM servers WHERE id = ?", (sid,)).fetchone()
        if not server:
            continue

        try:
            mysql_revoke_role(dict(server), role_name, grantee_user, grantee_host)
            db.execute(
                "DELETE FROM role_grants WHERE server_id = ? AND role_name = ? AND grantee_user = ? AND grantee_host = ?",
                (sid, role_name, grantee_user, grantee_host),
            )
            stmt = f"REVOKE '{role_name}' FROM '{grantee_user}'@'{grantee_host}'"
            db.execute(
                "INSERT INTO grant_history (server_id, server_name, grantee_user, grantee_host, privileges, databases, grant_statement, success, grant_type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'role')",
                (sid, server["name"], grantee_user, grantee_host, role_name, "[]", stmt),
            )
            db.commit()
            results.append({"server_name": server["name"], "ok": True})
        except Exception as e:
            stmt = f"REVOKE '{role_name}' FROM '{grantee_user}'@'{grantee_host}'"
            db.execute(
                "INSERT INTO grant_history (server_id, server_name, grantee_user, grantee_host, privileges, databases, grant_statement, success, error_message, grant_type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 'role')",
                (sid, server["name"], grantee_user, grantee_host, role_name, "[]", stmt, str(e)),
            )
            db.commit()
            results.append({"server_name": server["name"], "ok": False, "error": str(e)})

    return jsonify({"ok": True, "results": results})


@app.route("/roles/<int:server_id>/drop", methods=["POST"])
@auth_required
@csrf_protect
def roles_drop(server_id):
    data = request.get_json()
    role_name = data.get("role_name", "").strip()

    if not role_name:
        return jsonify({"ok": False, "error": "Role name is required."})

    db = get_db()
    server = db.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
    if not server:
        return jsonify({"ok": False, "error": "Server not found"}), 404

    try:
        mysql_drop_role(dict(server), role_name)
        db.execute("DELETE FROM roles WHERE server_id = ? AND role_name = ?", (server_id, role_name))
        db.execute("DELETE FROM role_grants WHERE server_id = ? AND role_name = ?", (server_id, role_name))
        stmt = f"DROP ROLE '{role_name}'"
        db.execute(
            "INSERT INTO grant_history (server_id, server_name, grantee_user, grantee_host, privileges, databases, grant_statement, success, grant_type) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'role')",
            (server_id, server["name"], role_name, "%", "DROP ROLE", "[]", stmt),
        )
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        stmt = f"DROP ROLE '{role_name}'"
        db.execute(
            "INSERT INTO grant_history (server_id, server_name, grantee_user, grantee_host, privileges, databases, grant_statement, success, error_message, grant_type) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 'role')",
            (server_id, server["name"], role_name, "%", "DROP ROLE", "[]", stmt, str(e)),
        )
        db.commit()
        return jsonify({"ok": False, "error": str(e)})


@app.route("/roles/set-default", methods=["POST"])
@auth_required
@csrf_protect
def roles_set_default():
    data = request.get_json()
    server_ids = data.get("server_ids", [])
    grantee_user = data.get("grantee_user", "").strip()
    grantee_host = data.get("grantee_host", "%").strip() or "%"
    default_role = data.get("default_role", "").strip()

    if not grantee_user or not server_ids or not default_role:
        return jsonify({"ok": False, "error": "Preencha usuário, role default e selecione servidores."})

    db = get_db()
    results = []

    for sid in server_ids:
        sid = int(sid)
        server = db.execute("SELECT * FROM servers WHERE id = ?", (sid,)).fetchone()
        if not server:
            continue

        try:
            mysql_set_default_role(dict(server), grantee_user, grantee_host, default_role)
            stmt = f"SET DEFAULT ROLE '{default_role}' TO '{grantee_user}'@'{grantee_host}'"
            db.execute(
                "INSERT INTO grant_history (server_id, server_name, grantee_user, grantee_host, privileges, databases, grant_statement, success, grant_type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'role')",
                (sid, server["name"], grantee_user, grantee_host, default_role, "[]", stmt),
            )
            db.commit()
            results.append({"server_name": server["name"], "ok": True})
        except Exception as e:
            stmt = f"SET DEFAULT ROLE '{default_role}' TO '{grantee_user}'@'{grantee_host}'"
            db.execute(
                "INSERT INTO grant_history (server_id, server_name, grantee_user, grantee_host, privileges, databases, grant_statement, success, error_message, grant_type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 'role')",
                (sid, server["name"], grantee_user, grantee_host, default_role, "[]", stmt, str(e)),
            )
            db.commit()
            results.append({"server_name": server["name"], "ok": False, "error": str(e)})

    return jsonify({"ok": True, "results": results})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5050, debug=False)
