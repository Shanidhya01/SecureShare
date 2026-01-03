# SecureShare

A full-stack secure file sharing app. Upload files, encrypt on the server, and share time-limited or one-time download links with simple audit visibility.

## Features
- Encrypted file storage with controlled access
- Time-limited and one-time download links
- Auth (register/login) with JWT
- Personal dashboard with file stats and link copy helpers
- Rate limiting and periodic cleanup of expired items
- Polished UI with toasts for feedback (login, register, upload, link copy, logout)

## Tech Stack
- Frontend: Next.js (App Router), Tailwind CSS, Axios, Lucide Icons, react-hot-toast
- Backend: Node.js, Express, MongoDB (Mongoose), Multer, JWT, node-cron, express-rate-limit
- Containerization: Docker, Docker Compose

## Monorepo Layout
- `frontend/` — Next.js client
- `backend/`  — Express API
- `docker-compose.yml` — Local dev for API + MongoDB

## Environment Variables

### Backend (`backend/.env`)
- `PORT` — API port (e.g., `5000`)
- `MONGO_URI` — MongoDB connection string
- `JWT_SECRET` — secret used to sign JWTs

### Frontend (`frontend/.env.local`)
- `NEXT_PUBLIC_API` — API base URL (e.g., `http://localhost:5000/api`)

Note: The frontend Axios client reads `NEXT_PUBLIC_API`. Ensure it points to your API base including `/api`.

## Local Development

### 1) Run with Node

Backend:
```bash
cd SecureShare/backend
npm install
npm run dev
```

Frontend:
```bash
cd SecureShare/frontend
npm install
npm run dev
```

- Frontend dev server: http://localhost:3000
- Backend API: http://localhost:5000 (endpoints under `/api`)

### 2) Run with Docker Compose
```bash
cd SecureShare
docker compose up --build
```
- API: http://localhost:5000
- MongoDB: mongodb://localhost:27017

## Core API Endpoints
- `POST /api/auth/register` — create account
- `POST /api/auth/login` — sign in (returns JWT)
- `POST /api/files/upload` — upload file (Auth required; multipart/form-data, field `file`)
- `GET /api/files/my-files` — list your files (Auth required)
- `GET /api/files/download/:id` — download link

## Frontend Notes
- Toasts are integrated globally via `Toaster` (top-right). Actions like login, register, upload, link copy, and logout show feedback.
- Set `NEXT_PUBLIC_API` so Axios requests reach your API (example: `http://localhost:5000/api`).

## Scripts

Backend:
- `npm run dev` — start API with Nodemon
- `npm start` — start API with Node

Frontend:
- `npm run dev` — start Next dev server
- `npm run build` — production build
- `npm start` — start production server

## Security & Cleanup
- Rate limiting protects the public API from abuse
- A scheduled cleanup job removes expired items

## License
This project is for educational/demo purposes.
