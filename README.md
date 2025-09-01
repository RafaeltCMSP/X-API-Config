# 🚀 X (Twitter) OAuth 2.0 + SQLite

Este projeto demonstra como implementar autenticação **OAuth 2.0 com PKCE** utilizando a **API do X (Twitter)**, salvando informações de **usuários** e **tweets** em um banco de dados **SQLite**.
Inclui fluxo de login, refresh de tokens, logout, sincronização de tweets e rotas de API para consulta.

---

## 📋 Funcionalidades

* 🔐 **Login com X (Twitter) via OAuth 2.0 + PKCE**
* 💾 **Banco SQLite integrado** para salvar usuários e tweets
* 👤 **Upsert de usuários** (inserção/atualização automática)
* 🧵 **Sincronização de tweets do usuário** autenticado
* 📊 **Dashboard simples em HTML** para visualizar dados
* 🔄 **Refresh de tokens**
* 🚪 **Logout com revogação do token no servidor X**
* ⚙️ **APIs REST** para consultas de usuário e tweets

---

## 🛠️ Tecnologias

* [Node.js](https://nodejs.org/) + [Express](https://expressjs.com/)
* [Axios](https://axios-http.com/)
* [SQLite3](https://www.sqlite.org/index.html)
* [dotenv](https://www.npmjs.com/package/dotenv)
* [express-session](https://www.npmjs.com/package/express-session)
* [crypto](https://nodejs.org/api/crypto.html)

---

## 📂 Estrutura de pastas

```
.
├── app.js            # Código principal (servidor Express + OAuth)
├── x_app.db          # Banco SQLite (gerado automaticamente)
├── public/           # Arquivos estáticos (se necessário)
├── .env              # Configurações locais (client_id, client_secret etc.)
└── README.md         # Documentação
```

---

## ⚙️ Configuração

### 1. Clonar o repositório

```bash
git clone https://github.com/seu-usuario/x-oauth-sqlite.git
cd x-oauth-sqlite
```

### 2. Instalar dependências

```bash
npm install
```

### 3. Criar arquivo `.env`

Exemplo de configuração:

```env
PORT=3000
BASE_URL=http://localhost:3000
REDIRECT_URI=http://localhost:3000/auth/callback

CLIENT_ID=SEU_CLIENT_ID
CLIENT_SECRET=SEU_CLIENT_SECRET   # opcional (para apps confidenciais)
SESSION_SECRET=uma_senha_segura_aqui

# Escopos do Twitter
X_SCOPES=tweet.read users.read follows.read like.read list.read bookmark.read offline.access
```

### 4. Criar app no **Developer Portal do X**

1. Acesse: [https://developer.twitter.com/](https://developer.twitter.com/)
2. Crie um novo projeto/app.
3. Configure o **Redirect URI** para o mesmo usado no `.env` (`REDIRECT_URI`).
4. Copie **Client ID** e **Client Secret** para o `.env`.

---

## ▶️ Executando o projeto

```bash
npm start
```

A aplicação estará disponível em:
👉 [http://localhost:3000](http://localhost:3000)

---

## 🌐 Rotas principais

### 🔑 Autenticação

* `GET /auth/login` → Inicia o fluxo OAuth
* `GET /auth/callback` → Callback do OAuth (definido no app do X)
* `GET /auth/refresh` → Renova o token de acesso
* `GET /auth/logout` → Revoga token e encerra sessão

### 📊 Interface Web

* `GET /` → Página inicial (login/logout)
* `GET /dashboard` → Dashboard com links para APIs

### 📡 APIs

* `GET /api/me` → Dados do usuário autenticado (salvos no SQLite)
* `GET /api/tweets` → Lista de tweets salvos no banco
* `GET /sync/tweets` → Sincroniza últimos tweets do usuário com a API do X

### 🔍 Utilitários

* `GET /health` → Healthcheck básico
* `GET /config` → Exibe configuração atual (scopes, redirect, etc.)

---

## 🗄️ Estrutura do Banco (SQLite)

### Tabela `users`

Campos principais:

* `user_id`, `username`, `name`, `description`
* `followers_count`, `following_count`, `tweet_count`
* `access_token`, `refresh_token`, `scope`, `expires_in`

### Tabela `tweets`

Campos principais:

* `id`, `user_id`, `text`, `created_at_twitter`
* `retweet_count`, `reply_count`, `like_count`, `quote_count`, `impression_count`

---

## 📖 Exemplo de uso

1. Acesse `http://localhost:3000`
2. Clique em **"Login com X"**
3. Autorize o app no Twitter
4. Você será redirecionado para o **Dashboard**
5. Clique em **/sync/tweets** para salvar seus tweets no banco
6. Acesse **/api/tweets** para ver os tweets sincronizados em formato JSON

---

## 🚧 Próximos passos (sugestões de melhoria)

* Implementar **UI completa** em React ou Next.js
* Adicionar gráficos de engajamento no dashboard
* Criar suporte a múltiplos usuários (multi-login)
* Adicionar **background jobs** para sincronização automática de tweets
* Melhorar **tratamento de erros** e logs

---

## 📜 Licença

Este projeto é distribuído sob a licença **MIT**.
Sinta-se livre para usar, modificar e compartilhar.

