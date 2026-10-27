# Tibia Market

Tibia Market is a mobile-first static React/PWA frontend with a separate Express/PostgreSQL API. The root `index.html` and `netlify/` directory are the current Netlify site; `deploy_v2/`, `deploy_v3/`, `tibia-market/`, and `tibia-market-pwa/` are historical copies and are not the configured root deployment.

## Backend setup

1. Install Node.js 18 or newer and PostgreSQL.
2. Copy `.env.example` to `.env`, then set `DATABASE_URL`, a random `JWT_SECRET` of at least 32 characters, and the exact deployed frontend origin in `CORS_ORIGINS`.
3. For local PostgreSQL without TLS, set `DATABASE_SSL=disable`. Leave it unset for a database with a valid TLS certificate.
4. Run `npm install`, then `npm start`.

The API creates missing tables and indexes on startup. On its first startup after this update, it revokes old sessions because those sessions were issued without character-ownership proof. It does not erase or migrate existing tables; review any existing schema before deploying these changes to a database that already contains production data.

After deployment, confirm that `https://<your-api-host>/health` returns HTTP 200 and reports a connected database before testing account creation. The frontend is currently configured to use `https://tibia-market-backend-production-c8af.up.railway.app`; if the Railway domain changes, update `API_URL` in `index.html` and redeploy the frontend. A running service without `DATABASE_URL` and a compatible deployed API build cannot create accounts.

## Character ownership

Registration, login, and adding a character now require a short-lived challenge in that character's public Tibia comment. Add the displayed code through Tibia's official account-management page, wait for TibiaData to reflect it, then retry verification. Remove the code from the public comment after verification. Never share your Tibia password.

The account screen persists the primary-character selection and only allows deleting a secondary character when no listings or conversations depend on it, preserving marketplace and chat history.

## Frontend deployment

Deploy the project root as the Netlify site. The API URL is currently configured in the frontend source as `API_URL` in `index.html`; update it to the deployed API origin when deploying to another backend. Configure the matching exact frontend URL in the API's `CORS_ORIGINS`. Character lookup falls back to TibiaData if the account API is unavailable, but this fallback cannot create an account.

## Product scope and remaining release work

- The social activity feed (level/profit posts, reactions, and comments) is not implemented yet; the current product is a marketplace with verified-character registration and messaging.
- Payments, escrow, and dispute resolution are not implemented. Trades are arranged directly by users; do not imply that the app guarantees delivery or payment.
- The character comment is public while the challenge code is present. The signed challenge expires after 30 minutes; users should remove the code once verification succeeds.
- Keep credentials in environment variables; never commit `.env`.
