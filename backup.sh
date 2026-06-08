#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_NAME="${PROJECT_NAME:-mysql-grant-manager}"

if [ -f "$SCRIPT_DIR/.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
fi

DB_NAME="${MGM_DB_NAME:-mysql_grant_manager}"
DB_ROOT_PASS="${MGM_DB_ROOT_PASS:-root}"
BACKUP_DIR="${SCRIPT_DIR}/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS="${BACKUP_RETENTION:-7}"

mkdir -p "$BACKUP_DIR"

CONTAINER=$(docker ps --filter "name=${PROJECT_NAME}-mysql" --format "{{.Names}}" 2>/dev/null | head -1)

if [ -z "$CONTAINER" ]; then
    CONTAINER=$(docker ps --filter "ancestor=mysql:8.0" --format "{{.Names}}" 2>/dev/null | head -1)
fi

if [ -z "$CONTAINER" ]; then
    echo "ERRO: Nenhum container MySQL em execucao encontrado."
    echo "Inicie com: docker compose up -d"
    exit 1
fi

BACKUP_FILE="$BACKUP_DIR/backup_${DB_NAME}_${TIMESTAMP}.sql.gz"

echo "Container : $CONTAINER"
echo "Banco     : $DB_NAME"
echo "Destino   : $BACKUP_FILE"

docker exec "$CONTAINER" mysqldump \
    -u root \
    -p"${DB_ROOT_PASS}" \
    --single-transaction \
    --routines \
    --triggers \
    --events \
    "$DB_NAME" | gzip > "$BACKUP_FILE"

SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo "OK: backup_${DB_NAME}_${TIMESTAMP}.sql.gz ($SIZE)"

DELETED=$(find "$BACKUP_DIR" -name "backup_*.sql.gz" -mtime +$RETENTION_DAYS -delete -print 2>/dev/null | wc -l)
if [ "$DELETED" -gt 0 ]; then
    echo "Limpeza : $DELETED backup(s) com mais de $RETENTION_DAYS dias removido(s)."
fi
