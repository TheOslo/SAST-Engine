# SAST frontend v2

React landing page and scanner UI. The original plain JavaScript frontend remains in `../frontend` as the preserved legacy copy.

## Development

```powershell
cd frontend-v2
npm install
npm run dev
```

Run the Flask backend in another terminal; Vite proxies `/api` and `/health` to `http://127.0.0.1:5000`. The overview is at `/` and the editor/scanner is at `/scanner`.

## Production

```powershell
cd frontend-v2
npm install
npm run build
cd ..
python -m backend.run
```

Flask serves `frontend-v2/dist` at `/` and `/scanner`, and exposes its files under `/assets/`.
