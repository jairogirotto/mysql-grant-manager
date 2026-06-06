#!/bin/bash
set -e

# Wait for MySQL to be ready
echo "Aguardando MySQL (${MGM_DB_HOST:-127.0.0.1}:${MGM_DB_PORT:-3306})..."
while ! python3 -c "
import pymysql, os, time
try:
    pymysql.connect(
        host=os.environ.get('MGM_DB_HOST', '127.0.0.1'),
        port=int(os.environ.get('MGM_DB_PORT', 3306)),
        user=os.environ.get('MGM_DB_USER', 'mgm'),
        password=os.environ.get('MGM_DB_PASS', 'mgm'),
        charset='utf8mb4',
        connect_timeout=3,
    ).close()
    exit(0)
except Exception:
    exit(1)
" 2>/dev/null; do
    echo "MySQL ainda nao esta pronto — aguardando..."
    sleep 2
done

echo "MySQL pronto. Inicializando banco..."
python3 -c "from app import init_db; init_db()"
exec gunicorn --workers 2 --bind 0.0.0.0:5050 app:app
