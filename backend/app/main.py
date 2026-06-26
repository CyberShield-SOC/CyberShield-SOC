from pathlib import Path
import sys

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.routers import upload

app = FastAPI(
    title="CyberShield SOC",
    description="Sprint 1 – Log Upload & Parsing API",
    version="1.0.0",
)


app.include_router(upload.router)
app.include_router(upload.router, prefix="/api")



@app.get("/health", tags=["Health"])
def health():
    from datetime import datetime, timezone
    return {
        "status": "ok",
        "service": "CyberShield SOC",
        "sprint": "1 - Log Upload & Parsing",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/", response_class=HTMLResponse, tags=["Frontend Preview"])
def upload_page():
    return """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <title>CyberShield SOC - Sprint 1</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 32px; background: #f7f9fc; color: #172033; }
        .card { background: white; padding: 24px; border-radius: 12px; box-shadow: 0 4px 18px rgba(0,0,0,.08); }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: white; }
        th, td { border: 1px solid #d8dee9; padding: 10px; text-align: left; }
        th { background: #102a43; color: white; }
        .error { color: #b00020; margin-top: 16px; font-weight: bold; }
        .success { color: #176b3a; margin-top: 16px; font-weight: bold; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>CyberShield SOC</h1>
        <p>Sprint 1: Upload a .log or .csv security log and view parsed results.</p>
        <input id="file" type="file" accept=".log,.csv" />
        <button onclick="uploadLog()">Upload & Parse</button>
        <div id="message"></div>
        <table id="results" style="display:none">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>IP Address</th>
              <th>Username</th>
              <th>Event Type</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <script>
        async function uploadLog() {
          const fileInput = document.getElementById("file");
          const message = document.getElementById("message");
          const table = document.getElementById("results");
          const tbody = table.querySelector("tbody");

          message.textContent = "";
          message.className = "";
          tbody.innerHTML = "";
          table.style.display = "none";

          if (!fileInput.files.length) {
            message.textContent = "Please choose a .log or .csv file first.";
            message.className = "error";
            return;
          }

          const formData = new FormData();
          formData.append("logfile", fileInput.files[0]);

          const response = await fetch("/upload", { method: "POST", body: formData });
          const data = await response.json();

          if (!response.ok || !data.success) {
            message.textContent = data.detail?.error || data.error || "Upload failed.";
            message.className = "error";
            return;
          }

          for (const entry of data.entries) {
            const parsed = entry.parsed || {};
            const row = tbody.insertRow();
            row.insertCell(0).textContent = parsed.timestamp || "-";
            row.insertCell(1).textContent = parsed.ip_address || "-";
            row.insertCell(2).textContent = parsed.username || "-";
            row.insertCell(3).textContent = parsed.event_type || "-";
            row.insertCell(4).textContent = parsed.status || "-";
          }

          message.textContent = `✓ Uploaded and parsed ${data.entries.length} log entries.`;
          message.className = "success";
          table.style.display = "table";
        }
      </script>
    </body>
    </html>
    """


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=3000, reload=True)
