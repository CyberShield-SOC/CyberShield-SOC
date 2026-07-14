from pathlib import Path
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.routers import alerts, incidents, upload, notes

app = FastAPI(
    title="CyberShield SOC",
    description="Sprint 1 – Log Upload & Parsing API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)

app.include_router(upload.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(notes.router)


app.include_router(upload.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(incidents.router, prefix="/api")
app.include_router(notes.router, prefix="/api")

_FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


@app.get("/health", tags=["Health"])
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
