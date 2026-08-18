# CommunicationX

CommunicationX is a Discord-style communication platform built with Flask, SQLAlchemy, Flask-Login, Socket.IO, and WebRTC.

## Authentication

CommunicationX now uses **local database authentication**.

- Sign up at `/signup`
- Log in with username or email at `/login`
- Passwords are stored as secure Werkzeug password hashes
- Sessions are handled by Flask-Login
- No third-party OAuth provider or provider-specific secrets are required

## Database

The app uses SQLAlchemy.

- **Local development:** SQLite (`communicationx.db`) is created automatically.
- **Production:** set `DATABASE_URL` to a PostgreSQL connection string.
- The database is separate from GitHub. GitHub stores the source code; your database stores users, messages, servers, etc.

Example:

```bash
DATABASE_URL=postgresql://user:password@host:5432/communicationx
SESSION_SECRET=replace-with-a-long-random-secret
```

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Open `http://127.0.0.1:5000`.

## GitHub deployment

Push this project to GitHub, then deploy the Python app on a host that supports persistent processes and WebSockets (for example Render, Railway, Fly.io, or a VPS). Configure `DATABASE_URL` and `SESSION_SECRET` as environment variables.

Do not commit `communicationx.db`, secrets, or `.env` files.

## Main stack

- Flask + SQLAlchemy
- Flask-Login
- Flask-SocketIO
- SQLite/PostgreSQL
- Jinja2 + Bootstrap
- WebRTC
