# MySQL Grant Manager

Aplicação web em Flask para administrar usuários, grants (privilégios) e **roles do MySQL 8** em múltiplos servidores MySQL remotos, a partir de uma única interface.

A ferramenta mantém um catálogo de servidores registrados e executa operações de `SHOW DATABASES`, descoberta de usuários, `GRANT`/`REVOKE`, criação/exclusão de roles e atribuição de roles diretamente contra cada servidor de destino, registrando tudo em um histórico de auditoria.

## Funcionalidades

- **Servidores**: cadastro, edição e exclusão de servidores MySQL de destino, com senha do usuário administrativo criptografada (Fernet), teste de conexão e refresh do cache de bancos de dados.
- **Grants**: criação de usuários e concessão de privilégios globais (`*.*`) e por banco (`\`db\`.*`) em múltiplos servidores simultaneamente, com *preview* do SQL antes da execução e revogação equivalente.
- **Roles (MySQL 8)**: sincronização, criação e exclusão de roles, atribuição/revogação de roles a usuários, definição de *default role* e concessão de privilégios a roles.
- **Histórico de auditoria**: registro paginado de todas as operações executadas (com o SQL gerado), sucesso/falha e mensagem de erro.
- **Segurança**: HTTP Basic Auth, proteção CSRF nos endpoints mutáveis e validações por *whitelist* de privilégios e identificadores MySQL (usuário/host/role) para prevenir SQL injection.

## Arquitetura

A aplicação tem duas responsabilidades de banco de dados:

1. **Banco de metadados (MGM)**: armazena as definições de servidores, credenciais criptografadas, cache de nomes de bancos, cache de roles/grants e o histórico de auditoria.
2. **Servidores de destino registrados**: consultados separadamente para `SHOW DATABASES`, descoberta de usuários, operações de grants/roles e alterações de conta.

### Backend (`mgm.py`)

O módulo `mgm.py` é monolítico e contém configuração, inicialização de schema, helpers de validação/segurança, operações MySQL nos servidores de destino e todas as rotas Flask.

- `get_db()`/`close_db()`: uma conexão PyMySQL ao banco MGM por requisição.
- `init_db()`: cria bancos/tabelas e aplica migrações de forma idempotente na inicialização.
- `mysql_connect(server)`: descriptografa a senha e abre conexão de tempo curto ao servidor de destino.
- Validações: `_validate_privileges()` (whitelist), `_validate_mysql_user_or_host()` e `_validate_role_name()` (identificadores).
- Rotas mutáveis usam `@auth_required` e `@csrf_protect`; rotas de leitura usam apenas Basic Auth.

### Tabelas de metadados

- `servers` — definições de conexão (senha criptografada).
- `server_databases` — cache de `SHOW DATABASES` (refrescado via `/servers/<id>/refresh`).
- `roles` e `role_grants` — cache local de roles e atribuições descobertas.
- `grant_history` — auditoria de grants, revokes, ações de usuário e de role.

### UI

UI server-rendered com Jinja2 + JavaScript/CSS puro (sem build system ou framework JS):

- `templates/base.html` — layout compartilhado, navegação, exposição do token CSRF.
- `templates/index.html` — dashboard.
- `templates/servers.html` — gestão de servidores, teste de conexão, refresh de bancos e ações de usuário.
- `templates/grants.html` — criação de usuários, preview/execução de grants e revokes, seleção de bancos.
- `templates/roles.html` — sincronização, criação/drop, atribuição, default role e privilégios de roles.
- `templates/history.html` — log de auditoria paginado.
- `static/style.css` — tema escuro compartilhado ("Command Center").

## Requisitos

- Python 3.12+
- MySQL 8.0 (as roles e o `mysql.role_edges` não têm a mesma semântica em versões anteriores)
- Um banco de dados MySQL para os metadados do MGM

## Instalação

### Desenvolvimento local

```bash
python3 -m venv venv
. venv/bin/activate
python -m pip install -r requirements.txt
```

Executar (requer um MySQL MGM acessível e as variáveis `MGM_*` configuradas):

```bash
python mgm.py
```

Ou em modo de produção com Gunicorn:

```bash
gunicorn --workers 2 --bind 0.0.0.0:5050 mgm:app
```

### Docker Compose

A imagem do app deve ser gerada com a tag `mgm:beta4`:

```bash
docker build -t mgm:beta4 .
docker compose up -d
docker compose logs -f app
docker compose down
```

O app fica disponível em `http://localhost:5050` e o MySQL em `3306`. O Compose sobe MySQL 8.0, aguarda o health check e o `entrypoint.sh` espera o banco, executa `init_db()` e inicia o Gunicorn.

Backup:

```bash
./backup.sh
```

O script localiza o container MySQL, gera um dump gzip em `backups/` e remove dumps mais antigos que `BACKUP_RETENTION` dias (padrão 7).

### Deployment (systemd)

```bash
./deploy.sh <host-destino>
```

Realiza deploy via SSH/rsync para `/opt/mysql-grant-manager`, cria virtualenv remoto, instala dependências, instala a unit systemd e reinicia o serviço.

## Configuração (variáveis de ambiente)

As variáveis são lidas na importação do módulo:

| Variável | Descrição | Padrão |
| --- | --- | --- |
| `MGM_DB_HOST` | Host do banco MGM | `127.0.0.1` |
| `MGM_DB_PORT` | Porta do banco MGM | `3306` |
| `MGM_DB_USER` | Usuário do banco MGM | `mgm` |
| `MGM_DB_PASS` | Senha do banco MGM | `mgm` |
| `MGM_DB_NAME` | Nome do banco MGM | `mysql_grant_manager` |
| `MGM_DB_ROOT_PASS` | Senha root do MySQL (Compose/backup) | `root` |
| `MGM_USER` | Usuário HTTP Basic Auth | `admin` |
| `MGM_PASS` | Senha HTTP Basic Auth | `admin` |
| `MGM_DATA_DIR` | Diretório persistente de chaves/sessões | `/var/lib/mysql-grant-manager` |
| `BACKUP_RETENTION` | Retenção de backups em dias | `7` |
| `PROJECT_NAME` | Prefixo do projeto Compose usado pelo `backup.sh` | — |

### Arquivos de chave (importantes)

- `MGM_DATA_DIR/.encryption_key` — criptografa as senhas administrativas dos servidores de destino (Fernet).
- `MGM_DATA_DIR/.secret_key` — chave de sessão do Flask.

**Preserve esses arquivos entre deploys.** Substituí-los invalida as credenciais armazenadas ou as sessões existentes. No Docker, eles vivem no volume `app_data`.

## Uso

1. Acesse `http://localhost:5050` e autentique-se com as credenciais Basic Auth (`MGM_USER`/`MGM_PASS`).
2. Registre um ou mais servidores MySQL de destino (host, porta, usuário administrativo e senha).
3. Use **Refresh** em cada servidor para popular o cache de bancos de dados.
4. Conceda/revogue grants, crie usuários e gerencie roles nas respectivas abas.
5. Acompanhe tudo no histórico de auditoria.

## Observações sobre o MySQL

- Privilegeios globais (incluindo `REPLICATION SLAVE`) são emitidos em `*.*`; os demais são emitidos por banco como `` `db`.* ``.
- Nomes de usuário e role são colocados entre aspas como identificadores de conta após validação por whitelist.
- A conta `root` é protegida: operações destrutivas a rejeitam.
- O cache de bancos não é atualizado automaticamente; fluxos que dependem de bancos atuais devem executar Refresh antes.

## Estrutura do projeto

```
mgm.py                      — Toda a lógica da aplicação e definição de schema
templates/*.html            — Formulários, chamadas fetch e estado da UI por rota
static/style.css            — Sistema visual compartilhado
docker-compose.yml          — Stack Compose (MySQL + app)
Dockerfile                  — Build da imagem do app
entrypoint.sh               — Espera o MySQL, roda init_db() e inicia o Gunicorn
backup.sh                   — Backup do banco via container
deploy.sh                   — Deploy systemd via SSH/rsync
mysql-grant-manager.service — Unit systemd (não-container)
my.cnf                      — Config MySQL montada no container
initdb/                     — Scripts init executados pelo MySQL na primeira subida
```