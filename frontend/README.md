# 🛡️ IDPS Platform — Frontend

Intrusion Detection & Prevention System — Next.js Frontend

## Tech Stack
- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS + Custom CSS
- **Icons**: Lucide React

## Getting Started

### 1. Install Dependencies
```bash
npm install
```

### 2. Run Development Server
```bash
npm run dev
```

Open [cyguardianx.vercel.app](cyguardianx.vercel.app) — it redirects to `/login`.

### 3. Demo Login Credentials
```
Email:    admin@idps.local
Password: admin123
```

## Project Structure

```
idps-platform/
├── app/
│   ├── layout.tsx          # Root layout
│   ├── page.tsx            # Redirects → /login
│   ├── globals.css         # Global styles + cyber theme
│   ├── login/
│   │   └── page.tsx        # 🔐 Login page
│   └── dashboard/
│       └── page.tsx        # 📊 Dashboard (placeholder)
├── components/             # Shared components (coming soon)
├── lib/                    # Utilities & API helpers
├── types/                  # TypeScript types
└── public/                 # Static assets
```

## Next Steps (Backend Integration)
1. Replace mock login with real API call to FastAPI backend:
   - `POST /api/v1/auth/login` → returns JWT token
2. Store JWT in `httpOnly` cookie
3. Add middleware for protected routes

## Backend (Python/FastAPI)
The backend service runs separately. See `/backend` directory (coming soon).

## Database (PostgreSQL)
Schema design coming next iteration.
