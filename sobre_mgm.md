# MySQL Grant Manager

Administração centralizada de acessos MySQL em múltiplos servidores.

## O que é

Uma aplicação web para gerenciar, de um só lugar, usuários, privilégios e perfis
(roles) do MySQL 8 em vários servidores remotos — sem precisar acessar cada
servidor individualmente.

## Principais recursos

- **Servidores** — Cadastre e gerencie múltiplos servidores MySQL, teste
  conexões e atualize o cache de bancos de dados de cada um.
- **Usuários** — Descubra usuários existentes, consulte seus privilégios, crie,
  bloqueie ou remova contas.
- **Grants** — Conceda ou revogue permissões em um ou vários servidores de uma
  vez, com pré-visualização do comando antes de executar.
- **Roles** — Sincronize, crie, remova e atribua roles do MySQL 8, defina roles
  padrão e gerencie privilégios por role.
- **Histórico de auditoria** — Registro completo de todas as operações, com o
  SQL gerado, servidor de destino e status (sucesso/erro).

## Segurança

- Acesso protegido por login (HTTP Basic Auth)
- Senhas dos servidores armazenadas de forma criptografada
- Proteção contra CSRF em todas as operações de escrita
- Validação dos identificadores e privilégios para evitar injeção de SQL
- Conta `root` protegida contra operações destrutivas

## A quem se destina

Equipes de DBA e operação que precisam gerenciar acessos a bancos MySQL de
forma centralizada, rastreável e segura, sem precisar de acesso manual a cada
instância.