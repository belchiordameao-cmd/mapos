# Varredura de Segurança — Map-OS

- **Data:** 2026-11-01
- **Commit analisado:** `fbfa5dc` (branch `master`, versão 4.55.3)
- **Método:** revisão estática de código (leitura e `grep`). Nenhum teste foi executado contra servidor, nenhum arquivo além deste relatório foi alterado.
- **Escopo pedido:** injeção SQL; autenticação/autorização em controllers e API; XSS e upload; execução de comando; segredos hardcoded; SSRF e path traversal; servidor Flask `pdf_server/server.py`.

> **Aviso sobre componentes não encontrados.** Os seguintes itens citados no escopo **não existem neste repositório**: `Api_os`, `Api_financeiro`, webhooks Cora/MZ/Meta, `qa2_resposta`, `euseflow_signup`, `wa_emergencia`, upload EuseFlow, `js/config.js` e `pdf_server/server.py` (não há nenhum arquivo `.py` nem código Flask). O repositório contém apenas o Map-OS upstream (PHP/CodeIgniter 3). Caso esses componentes vivam em outro repositório ou branch, precisam de uma varredura separada. A API analisada foi a existente em `application/controllers/api/v1/`.

Severidade: **Crítica** = tomada de controle ou execução remota sem precondição forte; **Alta** = escalação de privilégio, acesso a dados de outros ou RCE com precondição; **Média** = defesa em profundidade ausente com impacto real; **Baixa** = endurecimento / informativo.

---

## Crítica

Nenhum achado nesta categoria.

---

## Alta

| # | Arquivo:linha | Classe | Cenário de exploração (uma linha) |
|---|---|---|---|
| A1 | `application/controllers/api/v1/UsuariosController.php:130-137` e `:181` | Autorização quebrada / escalação de privilégio | No `PUT /api/v1/usuarios/{id}` qualquer usuário autenticado editando a **própria** conta passa pela checagem (só exige `cUsuario` quando `id` difere do seu) e o campo `permissoes_id` é aceito sem restrição, permitindo trocar o próprio perfil para administrador. |
| A2 | `application/controllers/api/v1/UsuariosController.php:184-186` | Armazenamento inseguro de credencial | No mesmo `PUT`, `senha` é gravada no banco **sem `password_hash`**, deixando a senha em texto claro e inutilizando o login (que usa `password_verify`); também permite ao usuário gravar uma string arbitrária como "hash". |
| A3 | `application/controllers/Cobrancas.php:56` | Carga dinâmica de classe / inclusão de arquivo controlada pelo usuário | `gateway_de_pagamento` vem do POST e é interpolado em `load->library("Gateways/$valor")`; a regra de validação (`form_validation.php:451-454`) é apenas `required|trim`, então um usuário com permissão `aCobranca` pode fazer o loader incluir outro arquivo PHP (inclusive com `../`) a partir de `application/libraries/` ou `system/libraries/`. |

---

## Média

| # | Arquivo:linha | Classe | Cenário de exploração (uma linha) |
|---|---|---|---|
| M1 | `application/views/os/editarOs.php:79,141-153`; `application/views/conecte/detalhes_os.php:80-95,283`; `application/views/vendas/editarVenda.php:41,77,84`; `application/views/clientes/editarCliente.php:105`; `application/views/conecte/editar_dados.php:22` (e ~40 ocorrências similares) | XSS armazenado (saída sem `html_escape`) | Campos gravados pelo usuário (descrição/defeito/observações de OS, nome do cliente, etc.) são ecoados dentro de `<textarea>` e atributos `value` sem escape; a única barreira é o `xss_clean` global na entrada (`config.php:517`), historicamente contornável, e um cliente autocadastrado no portal pode plantar o conteúdo que será renderizado no painel do operador. |
| M2 | `application/controllers/Login.php:25-75`; `application/controllers/Mine.php:176-229`; `application/controllers/api/v1/UsuariosController.php:242-305`; `application/controllers/api/v1/client/ClientLoginController.php:21-76` | Ausência de limitação de tentativas (brute force) | Nenhum dos quatro pontos de login tem rate limit, bloqueio por tentativas ou captcha, permitindo tentativa exaustiva de senha por e-mail conhecido. |
| M3 | `application/controllers/api/v1/client/ClientLoginController.php:24` e `application/controllers/api/v1/client/ClientOsController.php:134` | CORS permissivo | `Access-Control-Allow-Origin: *` em endpoint de autenticação do cliente; combinado com token no corpo da resposta, qualquer origem pode consumir a API caso o token seja guardado de forma acessível no front. |
| M4 | `application/controllers/api/v1/client/ClientLoginController.php:34-47` | Enumeração de contas | Mensagens distintas para "usuário não encontrado" e "senha incorreta" revelam quais e-mails de clientes existem (o login web em `Login.php:68-71` já corrige isso). |
| M5 | `application/libraries/REST_Controller.php:2273` | Autorização baseada em claim do token (sem releitura do banco) | O nível de permissão usado pela API vem de `permissao` dentro do JWT, não do banco; rebaixar ou desativar um usuário não invalida o token até expirar (`reGenToken` em `UsuariosController.php:312-322` checa `situacao`, mas as demais rotas não). |
| M6 | `application/controllers/Os.php:939-940`; `application/controllers/api/v1/OsController.php:852-853`; `application/controllers/Arquivos.php:226-227` | Upload sem limite de tamanho | `max_size => 0` (ilimitado) em anexos de OS e documentos; usuário autenticado pode esgotar disco. O tipo é validado (lista de extensões + MIME do CI), nome é aleatório e `.htaccess`/nginx bloqueiam execução em `anexos/` e `arquivos/`. |
| M7 | `application/controllers/Relatorios.php:197-215` | Ausência de checagem de permissão | `produtosEtiquetas` é o único método de relatório sem `checkPermission`; qualquer usuário logado gera o PDF de etiquetas com dados de produtos (`de_id`/`ate_id`), e esses parâmetros vão direto para o nome do arquivo no cabeçalho de download (`mpdf_helper.php:21`). |
| M8 | `application/controllers/Cobrancas.php:123,143,158,173,217` | Open redirect via `Referer` | `redirect($_SERVER['HTTP_REFERER'] ?? ...)` envia o usuário para qualquer URL presente no `Referer` após ações de cobrança (exige vítima autenticada e requisição iniciada de página controlada pelo atacante; CSRF reduz a praticidade). |
| M9 | `application/config/config.php:428-429` e `application/.env.example:20-21` | Cookies sem `Secure`/`HttpOnly` por padrão | `APP_COOKIE_SECURE=false` e `APP_COOKIE_HTTPONLY=false` como padrão de instalação; cookie de sessão trafega em HTTP e fica acessível a JS, agravando M1. |

---

## Baixa

| # | Arquivo:linha | Classe | Cenário de exploração (uma linha) |
|---|---|---|---|
| B1 | `application/libraries/Github_updater.php:75-87,98` | Confiança em resposta remota / cadeia de suprimento | O atualizador copia arquivos para caminhos vindos da resposta da API do GitHub (`$file->filename`) sem normalizar e depois roda `composer install` via `shell_exec`; exige permissão `cSistema` e comprometimento do repositório/branch configurado ou do canal TLS. |
| B2 | `application/controllers/Mapos.php:626-649` | Escrita no `.env` a partir de POST | Valores de SMTP e chaves de gateway vão para o `.env` com `str_replace`; quebras de linha são removidas (linha 634), mas aspas e `#` não são tratados, podendo corromper a leitura do arquivo (negação de serviço de configuração). Exige `cSistema`. |
| B3 | `index.php:77-86` e `install/index.php:46-52` | Redirecionamento baseado em `HTTP_HOST` | Antes da instalação, o redirect para `/install` usa o cabeçalho `Host` sem validação, permitindo envenenamento de cache/phishing se um proxy aceitar qualquer host. |
| B4 | `install/` (diretório inteiro, guarda em `install/do_install.php:58-63`) | Instalador acessível em produção | O instalador continua servido após a instalação; a reinstalação é bloqueada pela existência de `application/.env`, mas o diretório expõe versão/requisitos e aceita conexões a hosts MySQL arbitrários enquanto o `.env` não existir. Recomenda-se remover a pasta em produção. |
| B5 | `application/controllers/Relatorios.php:1017-1018` (e `1081-1082`) | Arquivo temporário com nome fixo em pasta pública | O relatório MEI gerado é gravado em `assets/relatorios/` (servido pelo web server) com nome fixo e só então apagado; janela de corrida permite leitura sem autenticação e sobrescrita entre usuários concorrentes. |
| B6 | `application/controllers/Mine.php:142-174` | Sem limite de solicitações de reset | `gerarTokenResetarSenha` enfileira um e-mail por requisição sem throttling, permitindo flood de e-mails para um cliente. Token em si é seguro (`random_bytes`, uso único, 24 h). |
| B7 | `application/controllers/Mine.php:279,296` | E-mail de cliente editável sem unicidade | Cliente autenticado no portal pode trocar o próprio e-mail para o de outro cliente; `check_credentials` usa `LIMIT 1`, então login e reset passam a depender da ordem das linhas (confusão de conta, sem ganho direto de acesso). |
| B8 | `application/views/relatorios/imprimir/imprimirEtiquetas.php:49,80,113,146` | Entrada refletida em atributo | `etiquetaCode` (GET) vai para o atributo `type` da tag `<barcode>` do mPDF sem escape; a saída é PDF, então não há XSS de navegador, mas pode quebrar/forçar erro na renderização. |
| B9 | `docker/.env:23-27` e `docker/docker-compose.yml:41-50,60-67` | Credenciais de desenvolvimento e serviços expostos | Senha root do MySQL trivial, phpMyAdmin com `PMA_ARBITRARY=1` e MySQL com porta publicada; aceitável apenas em ambiente local, perigoso se o compose for usado em servidor. |
| B10 | `application/controllers/Mapos.php:106` | Bug funcional com potencial de vazamento | `write_file(base_url() . 'backup/backup.zip', ...)` tenta gravar o dump do banco num caminho montado a partir da URL; hoje falha silenciosamente, mas se a URL coincidir com um caminho gravável, o backup completo fica numa pasta pública. |
| B11 | `application/controllers/Mapos.php:158,195` | Vazamento de erro interno | `print_r($upload_error)` devolve a mensagem crua da biblioteca de upload ao usuário (inclui caminho absoluto em alguns erros). |

---

## Verificado e considerado limpo

**1. Injeção SQL**
- Todos os `$this->db->query()` com variáveis usam bindings (`?`) ou `$this->db->escape()` (`Relatorios_model.php:135-160,201-216,395-410`; `Mapos_model.php:309-374`; `Produtos_model.php:78`). As migrations usam SQL estático.
- Buscas/autocomplete usam Query Builder (`like`, `where`) em todos os models (`Os_model`, `Vendas_model`, `Garantias_model`, `Financeiro_model`, `Api_model`, `Mapos_model::pesquisar`).
- `where($where)` com string só ocorre com valores internos (`MY_Email.php:181`, `UsuariosController.php:274,334` usa `(int)`).
- Não há `mysqli_*`/`PDO` fora do instalador (`install/do_install.php:39`, que usa `multi_query` com SQL do próprio `banco.sql`), e `php://input` é apenas decodificado para `$_POST` e consumido via `$this->post()` com validação.

**2. Autenticação e autorização**
- Todos os controllers web herdam `MY_Controller`, que exige sessão `logado` (`core/MY_Controller.php:42-44`); `Usuarios`, `Permissoes` e `Auditoria` checam permissão no construtor; demais métodos checam por ação (varredura automática: únicos sem checagem são helpers de formatação e `produtosEtiquetas`, reportado em M7).
- API: JWT HS256 com chave em `.env`, assinatura verificada com `hash_equals` (`third_party/php-jwt/JWT.php:240`), `alg` restrito à lista permitida (`JWT.php:96`), expiração verificada e renovação limitada a 2× o prazo (`Authorization_Token.php:123-127`). Tokens de cliente e de operador têm `type` distinto e não são intercambiáveis (`REST_Controller.php:2262-2267,2305-2310`).
- Portal do cliente (`Mine.php`) e API de cliente verificam que OS/venda/anexo pertencem ao cliente logado (`Mine.php:511,617,650,683,823,914`; `ClientOsController.php:79`; `ClientComprasController.php:66`).
- Login web e de cliente regeneram a sessão (`Login.php:56`, `Mine.php:198`), usam `password_verify`, mensagem única para usuário/senha inválidos e checam expiração de conta.
- Reset de senha do cliente: token `random_bytes(16)`, uso único, validade 24 h, resposta uniforme para e-mail inexistente (`Mine.php:142-174,932-958`).
- Captcha do cadastro é consumido por tentativa e não aceita sessão sem captcha (`Mine.php:843-856`).
- `Tools` e `Email` só respondem em CLI (`Tools.php:20`, `Email.php:17,26`). `do_upload*` são `protected` (não roteáveis).
- CSRF habilitado por padrão com regeneração; API excluída por usar Bearer (`config.php:445-450`).
- Hashes de senha nunca são retornados pela API ou models de listagem (`Usuarios_model.php:17-20` usa lista de colunas sem `senha`; `conta_get` remove `senha`).

**3. XSS e upload**
- 45 usos de `html_escape()` e 55 de `printSafeHtml()` (HTMLPurifier) nas views; `global_xss_filtering` ligado por padrão.
- Upload: lista de extensões + validação MIME do CodeIgniter; nome aleatório (`random_bytes`) mantendo só a extensão; `idOsServico` convertido para inteiro antes de compor o diretório (`Os.php:915`); `index.html` criado em cada pasta; `.htaccess` em `assets/anexos` e `assets/arquivos` e regra nginx (`docker/etc/nginx/default.template.conf:16`) bloqueiam execução de scripts; logos/avatares limitados a 2 MB e sem SVG (`Mapos.php:145-149`).

**4. Execução de comando**
- `shell_exec` em `MY_Email.php:117` usa apenas constantes da classe (`nohup php`, `FCPATH`, `email/process`), sem entrada externa.
- `proc_open`/`shell_exec` em `Github_updater.php:98,269` usam strings fixas (`which composer`, `composer install`), acionáveis só por `cSistema` (ver B1 sobre confiança na resposta remota).
- Não há `eval`, `system`, `passthru`, `popen` ou crases com variáveis no código da aplicação.

**5. Segredos**
- Nenhum segredo hardcoded em PHP ou JS (`assets/js/*.js` só contêm bibliotecas e lógica de UI; `csrf.js` lê o token do cookie).
- Chaves (`APP_ENCRYPTION_KEY`, `API_JWT_KEY`, credenciais de gateway e SMTP) vêm de `application/.env`, que está no `.gitignore` e não está versionado; `.env.example` contém apenas placeholders.
- Whoops só ativa em `development` com flag explícita e mascara variáveis do `.env` (`hooks/whoops.php:14-39`).

**6. SSRF e path traversal**
- Único `curl` da aplicação (`Github_updater.php:196-217`) aponta para `api.github.com` com usuário/repositório/branch vindos de arquivo de configuração, com `VERIFYPEER`/`VERIFYHOST` ativos; gateways de pagamento usam SDKs oficiais com URLs fixas.
- Rotas de download (`Os.php:1040-1056`, `Arquivos.php:170-187`, `Mine.php:891-922`) resolvem o caminho pelo ID numérico no banco, nunca por caminho enviado pelo usuário; `Relatorios.php:1004-1010` valida `format` contra lista fixa e usa `realpath` no template.
- `Seeder::call` só é alcançável via CLI.

**7. Servidor Flask (`pdf_server/server.py`)**
- Não existe no repositório (nenhum `.py`); nada a avaliar.

---

## Recomendações prioritárias (resumo)

1. **A1/A2:** no `index_put` da API de usuários, ignorar `permissoes_id`, `situacao` e `dataExpiracao` quando o alvo é o próprio usuário sem `cUsuario`, e aplicar `password_hash` em `senha`.
2. **A3:** validar `gateway_de_pagamento` contra as chaves de `config/payment_gateways.php` antes de `load->library`.
3. **M1/M9:** escapar saída com `html_escape()` nas views listadas e definir `APP_COOKIE_HTTPONLY=true` (e `SECURE` quando houver HTTPS) como padrão.
4. **M2:** adicionar limitação de tentativas nos quatro logins.
5. **M3/M4/M5:** restringir CORS, unificar mensagens de erro no login de cliente e reler `situacao`/`permissoes_id` do banco em `logged_user`.
6. **M6/M7/M8:** definir `max_size`, proteger `produtosEtiquetas` com `rProduto` e substituir `HTTP_REFERER` por rota fixa.
