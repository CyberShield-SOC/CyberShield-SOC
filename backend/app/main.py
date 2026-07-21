from pathlib import Path
import secrets
import sys

from fastapi import FastAPI
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import settings
from app.routers import alerts, auth, incidents, notes, upload, users

app = FastAPI(
    title="CyberShield SOC",
    description="Log Upload & Parsing API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://localhost:5173",
        "https://127.0.0.1:5173",
    ],
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    # Keep the browser contract explicit: credentialed requests may send JSON,
    # the CSRF value, and an optional bearer credential for non-browser clients.
    allow_headers=["Accept", "Authorization", "Content-Type", "X-CSRF-Token"],
    allow_credentials=True,
)


@app.middleware("http")
async def verify_browser_csrf(request: Request, call_next):
    """Protect cookie-authenticated writes with a double-submit CSRF token."""

    login_paths = {"/auth/login", "/api/auth/login"}
    has_bearer = request.headers.get("authorization", "").lower().startswith("bearer ")
    session_cookie = request.cookies.get(settings.auth_cookie_name)

    if (
        request.method in {"POST", "PUT", "PATCH", "DELETE"}
        and request.url.path not in login_paths
        and session_cookie
        and not has_bearer
    ):
        cookie_token = request.cookies.get(settings.auth_csrf_cookie_name)
        header_token = request.headers.get("x-csrf-token")
        if not cookie_token or not header_token or not secrets.compare_digest(cookie_token, header_token):
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF validation failed"},
            )

    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Apply conservative browser protections to API and hosted UI responses."""

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.path.startswith(("/auth/", "/api/auth/")):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    if settings.auth_cookie_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(upload.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(notes.router)
app.include_router(auth.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(upload.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(incidents.router, prefix="/api")
app.include_router(notes.router, prefix="/api")

_FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


@app.get("/health", tags=["Health"])
@app.get("/api/health", tags=["Health"], include_in_schema=False)
def health():
    from datetime import datetime, timezone
    return {
        "status": "ok",
        "service": "CyberShield SOC",
        "sprint": "1 - Log Upload & Parsing",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/", include_in_schema=False)
def root():
    index = _FRONTEND_DIST / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return HTMLResponse("""
    <!doctype html><html lang="en"><head><meta charset="utf-8"/>
    <title>CyberShield SOC</title>
    <style>body{font-family:Arial,sans-serif;margin:40px;background:#f7f9fc;color:#172033}</style>
    </head><body>
    <h1>CyberShield SOC — Backend Running</h1>
    <p>Build the frontend to serve the full app:
       <code>cd frontend &amp;&amp; npm install &amp;&amp; npm run build</code></p>
    <p>Or start the dev server:
       <code>cd frontend &amp;&amp; npm run dev</code> (connects via Vite proxy)</p>
    <p><a href="/health">/health</a> &nbsp; <a href="/docs">/docs</a></p>
    </body></html>
    """)


# Serve built React assets — must be mounted after all API routes
if (_FRONTEND_DIST / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(_FRONTEND_DIST / "assets")), name="assets")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=3000, reload=True)
