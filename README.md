# Local Auth API

## Run
```bash
npm install
cp .env.example .env
npm run dev
```

Health check: `GET http://localhost:4000/api/health`

## Routes
- `POST /api/auth/register` — fullName, email, mobile, password
- `POST /api/auth/login` — identifier (email/mobile), password
- `POST /api/auth/forgot-password` — identifier; returns a local-demo reset token
- `POST /api/auth/reset-password` — identifier, resetToken, newPassword

Passwords are hashed using bcryptjs. Login returns a short-lived demo JWT and public user details. The Flutter sample currently uses the returned user to demonstrate navigation; it does not persist or attach the JWT to authenticated requests.

## Demo limitations
Users are held in memory and disappear when the server restarts. Forgot password does not send email or SMS; a local-demo one-time token expires after 15 minutes and is returned by the API for testing. Add a database, real reset verification, request throttling, secure secret management, HTTPS, and tests before production use.
