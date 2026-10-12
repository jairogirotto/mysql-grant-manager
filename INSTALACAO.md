# Guia de Instalação — MySQL Grant Manager

Este documento descreve os passos para instalar e colocar o MySQL Grant Manager em funcionamento, tanto localmente quanto em produção.

## Obtendo o código-fonte

Clone o repositório:

```bash
git clone https://github.com/jairogirotto/mysql-grant-manager.git
cd mysql-grant-manager
```

## Requisitos

- **Python 3.12+** (para instalação local / Via Docker não é necessário)
- **MySQL 8.0/8.4** — servidor para armazenar os metadados do MGM (banco `mysql_grant_manager`)
- **Docker + Docker Compose** (opcional, instalação recomendada)
- Para os servidores-alvo gerenciados: **MySQL 8.0** (roles e `mysql.role_edges` exigem MySQL 8)

## Visão geral

A aplicação usa dois bancos distintos:

1. **Banco de metadados do MGM** — guarda servidores cadastrados, credenciais criptografadas, cache de bancos, cache de roles e o histórico de auditoria.
2. **Servidores-alvo** — cada servidor MySQL cadastrado é acessado individualmente para descoberta de usuários, grants, roles e alterações de conta.

---

## Opção 1 — Docker Compose  (fortemente recomendada) - todo o desenv foi feito em docker

Essa é a forma mais simples: sobe o MySQL e a aplicação juntos.

### 1.1. Configurar variáveis

Crie um arquivo `.env` na raiz do projeto (opcional — os padrões já funcionam):

```bash
MGM_DB_ROOT_PASS=root            # senha root do MySQL interno
MGM_DB_NAME=mysql_grant_manager
MGM_DB_USER=mgm
MGM_DB_PASS=mgm
MGM_USER=admin                   # usuário de login da interface web
MGM_PASS=foobar                  # senha de login da interface web
```

### 1.2. Build e subida

```bash
docker build -t mgm:latest .
docker compose up -d
docker compose logs -f app
```

O Compose inicia o MySQL 8.4, aguarda o health check e então o `entrypoint.sh`
prova o banco, roda `init_db()` e lança o Gunicorn.

### 1.3. Acesso

A aplicação fica disponível em `http://ip:5050`, com o MySQL exposto na porta `3306`.

### 1.4. Operação

```bash
docker compose ps              # status dos containers
docker compose restart app     # reinicia a aplicação
docker compose down            # derruba a stack
```

---

## Opção 2 — Instalação local (sem Docker)

### 2.1. Setup do Python

```bash
python3 -m venv venv
. venv/bin/activate
python -m pip install -r requirements.txt
```

### 2.2. Variáveis de ambiente

Configure as variáveis de conexão com o banco de metadados (veja a seção
[Configuração](#configuração)). O mínimo necessário, além de um MySQL acessível:

```bash
export MGM_DB_HOST=127.0.0.1
export MGM_DB_PORT=3306
export MGM_DB_USER=mgm
export MGM_DB_PASS=mgm
export MGM_DB_NAME=mysql_grant_manager
```

### 2.3. Inicializar o banco

```bash
python3 -c "from mgm import init_db; init_db()"
```

### 2.4. Subir o servidor

Desenvolvimento (Flask):

```bash
python mgm.py
```

Produção (Gunicorn):

```bash
gunicorn --workers 2 --bind 0.0.0.0:5050 mgm:app
```

---

## Opção 3 — Deploy via script (SSH/rsync + systemd)

Para implantar em um host remoto em `/opt/mysql-grant-manager` com serviço systemd:

```bash
./deploy.sh <host-destino>
# Ex: ./deploy.sh 10.0.0.50
```

O script:

1. Copia os arquivos via rsync (excluindo keys, venv e artefatos).
2. Cria o diretório de dados `/var/lib/mysql-grant-manager`.
3. Cria a venv e instala as dependências.
4. Instala e ativa o unit `mysql-grant-manager.service`.

Após o deploy, o serviço roda em `http://<host>:5050`.

> **Nota:** o serviço systemd usa o `MGM_DATA_DIR` padrão
> (`/var/lib/mysql-grant-manager`). As variáveis de conexão ao banco de
> metadados devem ser fornecidas via `/etc/systemd/system/mysql-grant-manager.service.d/override.conf`
> ou ambiente do sistema, conforme necessário.

---

## Configuração

As variáveis são lidas no momento do import do módulo. Valores padrão entre parênteses:

| Variável | Descrição | Padrão |
|---|---|---|
| `MGM_DB_HOST` | Host do banco de metadados | `127.0.0.1` |
| `MGM_DB_PORT` | Porta do banco de metadados | `3306` |
| `MGM_DB_USER` | Usuário do banco de metadados | `mgm` |
| `MGM_DB_PASS` | Senha do banco de metadados | `mgm` |
| `MGM_DB_NAME` | Nome do banco de metadados | `mysql_grant_manager` |
| `MGM_DB_ROOT_PASS` | Senha root do MySQL (Compose/backup) | `root` |
| `MGM_USER` | Login HTTP Basic Auth | `admin` |
| `MGM_PASS` | Senha HTTP Basic Auth | `admin` |
| `MGM_DATA_DIR` | Diretório persistente de chaves/sessões | `/var/lib/mysql-grant-manager` |
| `BACKUP_RETENTION` | Retenção de backups (dias) | `7` |
| `PROJECT_NAME` | Prefixo de containers usado pelo backup.sh | `mysql-grant-manager` |

### Arquivos de chave (IMPORTANTE)

O `MGM_DATA_DIR` guarda dois arquivos sensíveis — **preserve-os entre deploys**:

- `.encryption_key` — chave Fernet usada para criptografar as senhas dos servidores-alvo.
- `.secret_key` — chave de sessão do Flask.

Se esses arquivos forem substituídos ou perdidos, as credenciais armazenadas e as
sessões ficarão inutilizáveis. No Docker, ficam no volume `app_data`.

---

## Backup

```bash
./backup.sh
```

O script localiza o container MySQL em execução, gera um dump gzip sob `backups/`
e remove backups mais antigos que `BACKUP_RETENTION` dias (padrão 7). Ele pode
carregar variáveis de um `.env` local.

---

## Verificação rápida

```bash
# checa sintaxe do código Python
python3 -m py_compile mgm.py

# checa algum helper pontual
python3 -c "from mgm import _validate_privileges; print(_validate_privileges('SELECT, INSERT'))"
```

> Não há suíte de testes automatizada nem linter neste repositório.
