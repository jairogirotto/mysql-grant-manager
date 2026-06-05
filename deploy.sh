#!/bin/bash
set -e

TARGET_HOST="$1"
TARGET_DIR="/opt/mysql-grant-manager"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$TARGET_HOST" ]; then
    echo "Uso: ./deploy.sh <host-destino>"
    echo "Ex:   ./deploy.sh 10.0.0.50"
    exit 1
fi

echo "=== Copiando arquivos para $TARGET_HOST ==="
ssh "$TARGET_HOST" "mkdir -p $TARGET_DIR"

rsync -avz --exclude '__pycache__' --exclude '*.pyc' --exclude 'app.db' \
    --exclude '.encryption_key' --exclude 'venv' \
    "$SRC_DIR"/ "$TARGET_HOST:$TARGET_DIR/"

echo ""
echo "=== Criando diretorio de dados ==="
ssh "$TARGET_HOST" "mkdir -p /var/lib/mysql-grant-manager"

echo ""
echo "=== Instalando dependencias ==="
ssh "$TARGET_HOST" "python3 -m venv $TARGET_DIR/venv && \
    $TARGET_DIR/venv/bin/pip install -r $TARGET_DIR/requirements.txt"

echo ""
echo "=== Instalando systemd service ==="
ssh "$TARGET_HOST" "cp $TARGET_DIR/mysql-grant-manager.service /etc/systemd/system/ && \
    systemctl daemon-reload && \
    systemctl enable mysql-grant-manager && \
    systemctl restart mysql-grant-manager"

echo ""
echo "=== Status ==="
ssh "$TARGET_HOST" "systemctl status mysql-grant-manager --no-pager" || true

echo ""
echo "Deploy concluido: http://$TARGET_HOST:5050"
