# Forecast

**Forecast** is a full-stack cybersecurity forecasting and threat intelligence platform designed to turn security data into actionable insights.

## Overview

Forecast combines a modern React frontend with a FastAPI backend to provide a unified security console for authentication, threat detection, evidence, anomaly analysis, and forecasting workflows.

## Architecture

```text
Forecast
├── frontend/          # React + Vite frontend
├── backend/           # FastAPI application and core services
├── api/               # Vercel serverless entrypoint
├── vercel.json        # Vercel Services configuration
└── requirements.txt   # Production Python runtime dependencies
```

### Deployment flow

```text
Browser
   │
   ├── React / Vite frontend
   │
   └── /api/* requests
          │
          ▼
     FastAPI on Vercel
          │
          ├── Authentication
          ├── Threat Detection
          ├── Forecasting
          ├── Evidence
          └── Database
               │
               ▼
          PostgreSQL
```

## Core Features

- Secure analyst authentication with session-based JWT cookies
- User registration and login
- Threat and anomaly analysis APIs
- Cybersecurity forecasting workflows
- Evidence management
- Audit logging
- PostgreSQL-backed persistence
- FastAPI REST APIs
- React/Vite dashboard
- Vercel deployment with separate web and API services

## Technology Stack

**Frontend**
- React
- Vite
- Axios

**Backend**
- Python
- FastAPI
- SQLAlchemy
- Pydantic
- PostgreSQL / asyncpg
- JWT
- Argon2 password hashing
- scikit-learn
- NumPy
- Web3 / Ethereum tooling

**Infrastructure**
- Vercel
- GitHub
- PostgreSQL

## API Structure

The backend exposes API routes under `/api` and versioned application routes under `/api/v1`.

Authentication endpoints include:

```text
POST /api/auth/register
POST /api/auth/login
GET  /api/auth/me
POST /api/auth/logout
```

## Local Development

### 1. Clone the repository

```bash
git clone https://github.com/dhairyabansal-dev/Forecast.git
cd Forecast
```

### 2. Backend setup

```bash
python -m venv .venv
```

Windows:

```bash
.venv\\Scripts\\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install backend dependencies:

```bash
pip install -r backend/requirements.txt
```

### 3. Configure environment variables

Create the appropriate environment configuration for the backend. At minimum, production deployments require a secure `SECRET_KEY` and a valid PostgreSQL connection string such as `DATABASE_URL`.

Never commit production secrets, database credentials, API keys, or private tokens to the repository.

### 4. Start the backend

From the repository root:

```bash
uvicorn backend.app.main:app --reload
```

### 5. Start the frontend

```bash
cd frontend
npm install
npm run dev
```

## Production Deployment

The repository is configured for Vercel Services:

- `web` serves the Vite frontend from `frontend/`.
- `api` serves the FastAPI application through `api/index.py`.
- `/api/*` requests are routed to the FastAPI service.
- Other routes are served by the frontend.

Production environment variables should be configured in the Vercel project rather than committed to source control.

## Security

Forecast is intended for authorized security analysis and defensive use. Keep credentials and infrastructure secrets outside source control and use strong, rotated production secrets.

## Project Status

Forecast is under active development, with the platform architecture focused on a production-ready cybersecurity analyst console and forecasting workflow.
