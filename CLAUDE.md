# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

MySQL Grant Manager is a Flask web application for administering users, grants, and MySQL 8 roles across multiple remote MySQL servers. The application has two database responsibilities:

- The MGM metadata database stores registered server definitions, encrypted credentials, cached database names, role/grantee cache, and the grant audit history.
- Each registered target server is contacted separately for `SHOW DATABASES`, user discovery, grant/role operations, and account changes.

The UI is server-rendered Jinja2 with plain JavaScript and CSS; there is no frontend build system or JavaScript framework. The application is primarily Portuguese-language, though some API errors and operational messages are in English.

## Common commands

### Local Python development

Install dependencies into the active environment:

```bash
python3 -m venv venv
. venv/bin/activate
python -m pip install -r requirements.txt
```

Run the Flask development server (requires a reachable MGM MySQL database and suitable `MGM_*` variables):

```bash
python mgm.py
```

Run the production-style server directly:

```bash
gunicorn --workers 2 --bind 0.0.0.0:5050 mgm:app
```

Initialize or migrate the MGM schema without starting the web server:

```bash
python3 -c "from mgm import init_db; init_db()"
```

There is currently no automated test suite, test runner configuration, or linter in the repository. At minimum, compile-check Python changes before considering them complete:

```bash
python3 -m py_compile mgm.py
```

For a focused manual check of a Python helper, import it from a one-off command (after configuring the database environment), for example:

```bash
python3 -c "from mgm import _validate_privileges; print(_validate_privileges('SELECT, INSERT'))"
```

### Docker Compose

The Compose file expects the application image to be tagged `mgm:beta4`; build that tag before starting the stack:

```bash
docker build -t mgm:beta4 .
docker compose up -d
docker compose logs -f app
docker compose down
```

The app is exposed at `http://localhost:5050`; MySQL is exposed on port `3306`. Compose starts MySQL 8.0, waits for its health check, then `entrypoint.sh` probes the database, runs `init_db()`, and launches Gunicorn.

Useful operational commands:

```bash
docker compose ps
docker compose restart app
./backup.sh
```

`backup.sh` finds the running MySQL container, writes a gzipped dump under `backups/`, and removes dumps older than `BACKUP_RETENTION` days (default 7). It can load variables from a local `.env` file.

### Deployment

`deploy.sh` performs an SSH/rsync deployment to `/opt/mysql-grant-manager`, creates a remote virtualenv, installs `requirements.txt`, installs the systemd unit, and restarts the service:

```bash
./deploy.sh <target-host>
```

It assumes the caller has SSH access and sufficient remote privileges for systemd installation.

## Configuration

Configuration is read at module import time from environment variables:

```text
MGM_DB_HOST       MGM metadata DB host (default 127.0.0.1)
MGM_DB_PORT       MGM metadata DB port (default 3306)
MGM_DB_USER       MGM metadata DB user (default mgm)
MGM_DB_PASS       MGM metadata DB password (default mgm)
MGM_DB_NAME       MGM metadata DB name (default mysql_grant_manager)
MGM_DB_ROOT_PASS  Compose/backup MySQL root password (default root)
MGM_USER          HTTP Basic Auth username (default admin)
MGM_PASS          HTTP Basic Auth password (default admin)
MGM_DATA_DIR      Persistent key/session directory (default /var/lib/mysql-grant-manager)
BACKUP_RETENTION  Backup retention in days (default 7)
PROJECT_NAME      Compose project/container prefix used by backup.sh
```

`MGM_DATA_DIR/.encryption_key` encrypts target-server admin passwords with Fernet, and `MGM_DATA_DIR/.secret_key` is Flask's session key. Preserve these files across deployments; replacing them makes stored credentials or sessions unusable. Docker persists them in the `app_data` volume.

## Architecture and request flow

### Backend (`mgm.py`)

`mgm.py` is intentionally monolithic: configuration, schema initialization, validation/security helpers, target-server MySQL operations, and all Flask routes live in one module.

- `get_db()` creates one PyMySQL connection to the MGM metadata database per Flask request and stores a small wrapper in `flask.g`; `close_db()` closes it at teardown.
- `init_db()` creates the metadata database and tables if needed, then applies the existing `servers.descricao` compatibility migration. Schema changes should generally be added here in an idempotent way because startup invokes this function.
- `mysql_connect(server)` decrypts the stored target password and opens a short-timeout connection to the selected target server. Target connections are separate from the MGM metadata connection and are explicitly closed by each helper.
- Validation helpers protect interpolated MySQL syntax: `_validate_privileges()` uses an allowlist, `_validate_mysql_user_or_host()` and `_validate_role_name()` restrict account identifiers, and `_safe_identifier()` quotes database identifiers. Keep these validations in the path before adding SQL built from request data.
- Mutating routes use both `@auth_required` and `@csrf_protect`; JSON clients must send the session token as `X-CSRF-Token` (or form posts can use `_csrf_token`). Read routes require Basic Auth only.
- Grant, revoke, user, and role operations execute against target servers and then append success/failure records to `grant_history`. Multi-server requests process each selected server independently and return per-server result objects.

### Metadata tables

The schema created in `init_db()` contains:

- `servers`: target connection information; target passwords are encrypted before storage.
- `server_databases`: cached `SHOW DATABASES` results, refreshed explicitly through `/servers/<id>/refresh`.
- `roles` and `role_grants`: local cache of discovered/managed MySQL roles and role assignments.
- `grant_history`: audit records for grants, revokes, user actions, and role actions, including generated SQL, target server, status, and error text.

Foreign keys clean up cached rows when a server is deleted. The database cache is not automatically refreshed; UI flows that need current databases should refresh first or use the existing cached list.

### UI structure

- `templates/base.html` supplies the shared layout, navigation, CSRF token exposure, and common client-side behavior.
- `templates/index.html` is the dashboard.
- `templates/servers.html` manages target definitions, connection tests, database refreshes, and target user actions.
- `templates/grants.html` drives multi-server user creation, grant preview/execute, revoke preview/execute, and database selection.
- `templates/roles.html` drives role synchronization, creation/drop, role assignment, default-role settings, and privileges granted to roles.
- `templates/history.html` displays the paginated audit log.
- `static/style.css` contains the shared dark “Command Center” styling; use its existing variables and component patterns rather than introducing a separate styling system.

The browser talks to JSON endpoints for most grant/role/server actions. When changing a payload, update the corresponding plain-JavaScript function in the template and its Flask route together. The role privilege endpoint accepts either a comma-separated string or an array of database names; an empty selection currently falls back to all cached databases for each target server.

## MySQL-specific behavior

The app targets MySQL 8.0. Roles and `mysql.role_edges` are not available with the same semantics on older MySQL versions. Global-only privileges (including `REPLICATION SLAVE`) are split from database-level privileges and emitted on `*.*`; other privileges are emitted per selected database as `` `database`.* ``. User and role names are quoted as MySQL account identifiers after allowlist validation.

Do not assume an MGM server registration means its database cache is current. A missing cache commonly causes grant execution to report that Refresh is required. Also preserve the protected-user behavior: destructive operations reject the `root` account in the relevant routes.

## Files worth consulting for changes

- `mgm.py`: all application behavior and schema definition.
- `templates/*.html`: route-specific forms, fetch calls, and UI state.
- `static/style.css`: shared visual system.
- `docker-compose.yml`, `Dockerfile`, `entrypoint.sh`: container build/startup contract.
- `mysql-grant-manager.service`: non-container systemd deployment.
- `implementacao.txt` and `alteracoes/`: project-specific implementation notes and prior change documentation; treat them as design context, then verify behavior against current code.

Generated/runtime material such as `.env`, key files, sessions, logs, `__pycache__`, and backups are ignored by Git. Avoid adding those artifacts to commits.
