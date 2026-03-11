# Warden — Frontend

The Open Source Vulnerability Orchestrator · React 18 · TypeScript · Vite · Tailwind CSS

---

## Accessing the UI

### Development mode (two terminals)

**Terminal 1 — start the API:**
```bash
cd warden
uvicorn api.main:app --reload --port 8000
```

**Terminal 2 — start the UI:**
```bash
cd warden/frontend

npm install        # first time only
npm run dev
```

Open your browser at **http://localhost:5173**

Log in with the credentials from your `.env` file:
- **Username:** value of `AUTH_USERNAME` (default: `admin`)
- **Password:** value of `AUTH_PASSWORD` (default: `warden-changeme`)

> Change the defaults in `.env` before exposing the app to a network.

---

### Production mode (Docker)

```bash
cd warden/frontend

npm run build                  # compiles to frontend/dist/
cd ..
docker compose up -d           # starts api + ui + db + redis + worker
```

Open your browser at **http://localhost**

The UI is served by nginx on port 80. The API runs on port 8000 and is proxied automatically — no separate API URL needed.

---

### Changing your password

Edit `.env` in the project root and restart the API:
```bash
# .env
AUTH_USERNAME=admin
AUTH_PASSWORD=your-new-password
WARDEN_SECRET_KEY=your-random-secret   # generate: python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## Pages

| Route | What it shows |
|-------|---------------|
| `/login` | Sign in with username and password |
| `/` | Dashboard — live metrics, KEV exposure, risk trend, scanner coverage |
| `/findings` | Full findings table with filters, inline status updates, detail panel |
| `/kev` | CISA KEV alerts grouped by urgency and days remaining |
| `/pipeline` | Trigger a full scan or KEV sync, monitor task status |
| `/reports` | Download CSV reports, copy BI tool connection info |

---

## Tech Stack

| Layer | Library |
|-------|---------|
| Framework | React 18 + TypeScript |
| Build | Vite 5 |
| Styling | Tailwind CSS 3 |
| Charts | Recharts |
| Icons | Lucide React |
| Routing | React Router v6 |
| HTTP | Native fetch (no axios) |

---

## Development notes

- All API calls proxy to `http://localhost:8000` via Vite's dev server — no CORS setup needed in dev.
- JWT token is stored in `localStorage` under the key `warden_token`.
- To point at a different backend URL, change the `target` in `vite.config.ts` and `BASE_URL` in `src/api.ts`.
- Run `npm run build` then open `dist/index.html` in a static file server — not directly in a browser (React Router requires a server for client-side routing).
