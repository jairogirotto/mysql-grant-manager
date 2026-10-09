# Sugestões de melhorias

Este documento reúne melhorias sugeridas para o MySQL Grant Manager, organizadas por área e prioridade.

## Prioridade recomendada

As cinco melhorias com melhor relação entre segurança, confiabilidade e esforço são:

1. Criar testes para validação e geração de SQL.
2. Remover ou bloquear credenciais padrão em produção.
3. Melhorar o tratamento e a visualização de resultados multi-servidor.
4. Adicionar idade e status explícitos ao cache de databases.
5. Centralizar a geração de SQL antes de dividir o monólito.

## 1. Corrigir padrões inseguros de configuração

Os valores padrão atuais são convenientes para desenvolvimento, mas perigosos em uma rede acessível:

```text
MGM_USER=admin
MGM_PASS=admin
MGM_DB_PASS=mgm
MGM_DB_ROOT_PASS=root
```

Sugestões:

- Exigir `MGM_USER` e `MGM_PASS` em produção.
- Falhar na inicialização se credenciais padrão forem usadas fora de um modo explicitamente configurado para desenvolvimento.
- Criar um `.env.example` sem senhas reais.
- Adicionar uma configuração como `MGM_ENV=development|production`.
- Em produção, rejeitar combinações padrão como `admin/admin`, `mgm/mgm` e `root/root`.

## 2. Adicionar uma suíte mínima de testes

O projeto não possui testes automatizados. Uma suíte inicial pode cobrir funções que não exigem um MySQL real:

- `_validate_privileges()`.
- `_validate_mysql_user_or_host()`.
- `_validate_role_name()`.
- `_safe_identifier()`.
- `_escape_mysql_string()`.
- Separação entre privilégios globais e privilégios por database.
- Geração de SQL de `GRANT` e `REVOKE`.
- Rejeição do usuário `root`.
- Validação de CSRF.
- Autenticação HTTP Basic.

Depois, adicionar testes de rotas com `Flask test_client` e mocks para as conexões MGM e target.

Estrutura inicial:

```text
tests/
├── conftest.py
├── test_validation.py
├── test_auth.py
├── test_grant_sql.py
├── test_routes_grants.py
└── test_routes_roles.py
```

Dependências e comando sugeridos:

```bash
python -m pip install pytest
pytest -q
```

## 3. Dividir gradualmente o `mgm.py`

O arquivo monolítico concentra configuração, banco, segurança, operações MySQL e rotas. Uma divisão gradual reduziria o custo de manutenção:

```text
mgm/
├── __init__.py
├── config.py
├── database.py
├── security.py
├── target_mysql.py
├── grants.py
├── roles.py
└── routes/
    ├── servers.py
    ├── grants.py
    ├── roles.py
    └── history.py
```

Sequência sugerida:

1. Extrair validações e funções de segurança.
2. Extrair geração e execução de SQL de grants.
3. Extrair operações de roles.
4. Extrair as rotas para blueprints.
5. Manter `mgm.py` como ponto de entrada compatível.

Não é recomendável fazer toda a migração de uma vez.

## 4. Fortalecer sessão e autenticação

HTTP Basic Auth deve ser usado somente com HTTPS fora do ambiente local.

Sugestões:

- Documentar a exigência de HTTPS.
- Usar `SESSION_COOKIE_SECURE=True` em produção.
- Usar `SESSION_COOKIE_HTTPONLY=True`.
- Usar `SESSION_COOKIE_SAMESITE="Lax"` ou `"Strict"`.
- Considerar autenticação baseada em sessão após o primeiro login.
- Adicionar limitação de tentativas ou rate limiting.
- Evitar mensagens que revelem detalhes desnecessários dos servidores MySQL.
- Garantir que senhas descriptografadas não apareçam em logs ou mensagens de erro.

## 5. Melhorar o gerenciamento das chaves criptográficas

As credenciais dos servidores são protegidas por Fernet, mas a segurança depende da preservação de:

```text
MGM_DATA_DIR/.encryption_key
MGM_DATA_DIR/.secret_key
```

Sugestões:

- Verificar permissões dos arquivos, idealmente `0600`.
- Falhar de forma explícita se as chaves não puderem ser criadas ou lidas.
- Documentar que essas chaves precisam fazer parte do backup.
- Criar um procedimento de rotação de chave.
- Permitir fornecimento da chave via secret manager em ambientes orquestrados.
- Informar claramente que a perda de `.encryption_key` torna as senhas armazenadas irrecuperáveis.

Uma rotação segura deve descriptografar com a chave antiga, criptografar com a nova e substituir a chave somente após a migração ser concluída com sucesso.

## 6. Tornar operações multi-servidor mais claras

Como cada servidor é processado independentemente, uma operação pode ter sucessos, falhas e servidores indisponíveis na mesma requisição.

Sugestões:

- Retornar uma estrutura padronizada por servidor.
- Diferenciar `success`, `failed`, `skipped` e `unreachable`.
- Exibir contadores no frontend.
- Permitir repetir apenas os servidores que falharam.
- Registrar o motivo e o SQL gerado no histórico.
- Usar um identificador comum para agrupar os resultados da operação.

Exemplo:

```json
{
  "operation_id": "...",
  "summary": {
    "total": 5,
    "success": 2,
    "failed": 2,
    "skipped": 1
  },
  "results": []
}
```

## 7. Melhorar a consistência dos caches

O cache de databases, usuários e roles pode ficar desatualizado e depende de atualização explícita.

Sugestões:

- Registrar `updated_at` no cache.
- Exibir a idade do cache na interface.
- Avisar quando o cache estiver antigo.
- Permitir refresh automático sob demanda.
- Oferecer a opção “Atualizar antes de executar”.
- Diferenciar cache vazio de um servidor realmente sem databases.
- Invalidar caches relacionados após operações de criação ou remoção.
- Guardar timestamp da última sincronização de roles.

A interface deve distinguir claramente:

```text
Nenhum banco carregado. O cache ainda não foi atualizado.
```

de:

```text
Este servidor não possui bancos.
```

## 8. Centralizar a geração de SQL

As regras de privilégios globais e por database devem ser isoladas em funções puras, sem conexão com banco ou Flask.

Exemplo conceitual:

```python
statements = build_grant_statements(
    user="usuario",
    host="%",
    privileges=["SELECT", "REPLICATION SLAVE"],
    databases=["app", "billing"],
)
```

Benefícios:

- Testar combinações de privilégios isoladamente.
- Gerar preview e execução a partir da mesma fonte.
- Evitar divergência entre preview e execução.
- Garantir que `REPLICATION SLAVE` continue em `*.*`.
- Garantir que identificadores e contas sejam sempre validados e escapados.

O endpoint de preview também poderia retornar uma estrutura semântica, além do SQL textual:

```json
{
  "scope": "*.*",
  "privileges": ["REPLICATION SLAVE"],
  "databases": []
}
```

## 9. Melhorar auditoria e rastreabilidade

O histórico já é uma funcionalidade importante. Pode ser ampliado com:

- Usuário MGM que iniciou a operação.
- IP ou identificador do cliente, quando apropriado.
- Identificador da operação.
- Timestamp com timezone consistente.
- Conta-alvo completa.
- Servidor-alvo.
- Resultado por servidor.
- Motivo da operação.
- Distinção entre preview e execução.
- Versão da aplicação que gerou a operação.

SQL de criação de usuários não deve registrar senhas em texto claro. A cláusula de senha deve ser omitida ou mascarada no histórico.

## 10. Melhorar o Docker Compose

O Compose atualmente usa a imagem existente `mgm:beta4`, exigindo uma construção manual:

```bash
docker build -t mgm:beta4 .
docker compose up -d
```

Para desenvolvimento, considerar `build` diretamente no Compose ou arquivos separados:

```text
docker-compose.yml
docker-compose.dev.yml
docker-compose.prod.yml
```

Outras sugestões:

- Adicionar healthcheck para o serviço `app`.
- Usar `restart: unless-stopped` em produção.
- Separar volumes de desenvolvimento e produção.
- Criar `.env.example`.
- Não expor a porta do MySQL publicamente em produção quando não for necessário.
- Evitar senhas padrão no ambiente de produção.

## 11. Melhorar o script de backup

O `backup.sh` cobre o caso básico, mas pode ser fortalecido com:

- Validação de que `BACKUP_RETENTION` é numérico.
- Tratamento explícito de falha do `mysqldump`.
- Remoção do arquivo parcial quando o dump falhar.
- Verificação de espaço livre.
- Checksum do arquivo gerado.
- Opção de destino externo.
- Teste periódico de restauração.
- Limpeza de temporários antigos.
- Carregamento mais robusto do `.env`, evitando depender de `export $(... | xargs)` para valores com espaços ou caracteres especiais.

Criar o backup não é suficiente; é necessário validar a restauração em um banco temporário:

```bash
gunzip -c backup.sql.gz | mysql ...
```

## 12. Adicionar observabilidade básica

Para uma ferramenta que administra servidores remotos, seria útil registrar:

- Logs estruturados.
- Duração de cada operação.
- Servidor-alvo.
- Tipo da operação.
- Resultado.
- Exceção completa no log interno.
- Mensagem sanitizada para a interface.
- Endpoint de healthcheck do MGM.
- Endpoint separado para testar dependências.
- `request_id` ou `operation_id` para correlacionar logs e histórico.

## 13. Melhorar acessibilidade e usabilidade

A evolução documentada em `implementacao.txt` para seleção de databases em roles pode ser implementada com drag-and-drop HTML5, desde que haja alternativas acessíveis.

Sugestões:

- Manter seleção por teclado.
- Não depender exclusivamente de drag-and-drop.
- Usar botões reais para adicionar e remover databases.
- Fornecer estados vazios claros.
- Indicar cache desatualizado.
- Explicar quando “nenhuma database selecionada” significa “todas”.
- Confirmar operações destrutivas.
- Destacar o usuário `root` como protegido.
- Mostrar resultados individuais por servidor.

A seleção global de databases é coerente com a semântica atual do backend, mas isso deve ser comunicado claramente na interface.

## 14. Adicionar ferramentas de qualidade

Como evolução gradual, considerar:

```text
pytest
ruff
mypy
```

Comandos iniciais:

```bash
ruff check .
python3 -m py_compile mgm.py
pytest -q
```

Um `pyproject.toml` pode centralizar a configuração do Ruff, pytest, versão mínima do Python e exclusões de arquivos gerados. O `mypy` pode ser introduzido posteriormente, de forma progressiva.
