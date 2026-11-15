from __future__ import annotations

from fastapi import Request

from app.core.config import settings


def frontend_base_url(request: Request) -> str:
    """Return the trusted frontend origin used in emailed links (password
    reset, account invites).

    Explicit FRONTEND_BASE_URL wins. Railway's injected public domain is used
    next for the combined deployment. Local development falls back to Vite;
    other deployments fall back to the request origin served by FastAPI.
    """

    configured = (settings.frontend_base_url or "").strip().rstrip("/")
    railway_domain = (settings.railway_public_domain or "").strip().rstrip("/")

    # If Railway is running the app, never let an old local-dev value such as
    # https://127.0.0.1:5173 leak into a real user's email.
    configured_is_local = configured.startswith((
        "http://localhost",
        "https://localhost",
        "http://127.0.0.1",
        "https://127.0.0.1",
    ))
    if railway_domain and (not configured or configured_is_local):
        if railway_domain.startswith(("http://", "https://")):
            return railway_domain
        return f"https://{railway_domain}"

    if configured:
        return configured

    host = (request.url.hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "testserver"}:
        return "https://127.0.0.1:5173"

    return str(request.base_url).rstrip("/")
