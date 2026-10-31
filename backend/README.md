# SAST backend

The backend exposes the Flask scan and CWE catalog API. Analyzer rules are bundled as Python modules; MySQL stores the selectable CWE catalog and metadata-only scan telemetry.

## Setup

1. Install Python 3.10 or newer and MySQL 8.0.16 or newer.
2. From the repository root, install dependencies:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r backend\requirements.txt
   ```

3. Create the database and seed its seven-CWE catalog:

   ```powershell
   mysql -u root -p
   ```

   At the MySQL prompt, run `SOURCE C:/path/to/SAST/backend/schema.sql;` using the absolute path to this checkout.

4. Create a least-privilege application account in MySQL, replacing the sample password:

   ```sql
   CREATE USER 'sast_app'@'127.0.0.1' IDENTIFIED BY 'replace-this-password';
   GRANT SELECT ON sast_engine.cwe TO 'sast_app'@'127.0.0.1';
   GRANT SELECT ON sast_engine.cwe_list TO 'sast_app'@'127.0.0.1';
   GRANT SELECT ON sast_engine.cwe_list_member TO 'sast_app'@'127.0.0.1';
   GRANT INSERT ON sast_engine.scan_telemetry TO 'sast_app'@'127.0.0.1';
   ```

5. Set the `MYSQL_*` environment variables shown in `backend/.env.example` before starting the API.

The production frontend build is included in `frontend-v2/dist`, so Flask can start directly. After changing frontend source files, rebuild it:

   ```powershell
   cd frontend-v2
   npm install
   npm run build
   cd ..
   ```

Start Flask from the repository root:

   ```powershell
   python -m backend.run
   ```

The API listens on `http://127.0.0.1:5000` by default. The example environment file documents settings; it is not loaded automatically. In PowerShell, set variables with `$env:MYSQL_USER = 'sast_app'` and `$env:MYSQL_PASSWORD = 'replace-this-password'` before starting it.

Open `http://127.0.0.1:5000/` for the SAST overview or `http://127.0.0.1:5000/scanner` for the editor and scanner. The original plain JavaScript frontend is preserved in `frontend/`; Flask serves the built React app from `frontend-v2/dist`. The Monaco editor is loaded from jsDelivr, so a browser needs access to that CDN; if it cannot load, the page falls back to a basic textarea.

The browser limits individual `.py` uploads to 1 MiB. The backend defaults to a 3 MiB JSON request limit to allow for JSON encoding overhead; adjust `MAX_CONTENT_LENGTH` if you change the upload limit.

## Endpoints

- `GET /health` returns process liveness without requiring MySQL.
- `GET /api/cwes` returns the seven selectable CWE records in catalog order.
- `POST /api/scan` accepts JSON with `source_code`, optional `cwe_ids` (default `[89]`), and optional `custom_instructions`.

Example scan body:

```json
{
  "source_code": "value = request.args.get('q')\\ninternal_query(value)",
  "cwe_ids": [89],
  "custom_instructions": {
    "sinks": ["internal_query"],
    "tracked_variables": ["value"]
  }
}
```

Custom sinks use built-in request sources and appear under `custom_findings`; tainted assignments to tracked variables appear under `custom_observations`. The response also includes `sanitized_flows` for paths stopped by a sanitizer recognized for a selected CWE, currently CWE-79 `escape` and `conditional_escape` calls. Scan telemetry stores selected CWE IDs, duration, and result counts only. It never stores submitted source code, detailed findings, or per-scan custom instructions.

If MySQL is unavailable, scanning continues with bundled rules and logs the telemetry failure; `GET /api/cwes` returns HTTP 503.
