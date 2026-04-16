import uvicorn
import os
import base64
import httpx
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi import Request
import pandas as pd
from pathlib import Path
import asyncio
import joblib
import json
from datetime import datetime
import logging
from pydantic import BaseModel
import uuid
from contextlib import asynccontextmanager
from predictor_py import predict_url
from info_from_ip import dns_rec
from threatmap import build_threat_event

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

BASE_DIR      = Path(__file__).resolve().parent.parent
feature_order = joblib.load(Path(__file__).resolve().parent / "Model" / "feature_order1.pkl")
DROPPED_COLS  = {"URL", "Domain", "TLD", "Title"}

# Playwright service URL — injected via env var in docker-compose
PLAYWRIGHT_URL = os.getenv("PLAYWRIGHT_SERVICE_URL", "http://playwright:3000")

url_history = []


# ── Request model ──────────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    url: str


# ── Model loaded once at startup ───────────────────────────────────────────
model = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global model
    logger.info("Loading model...")
    try:
        model = joblib.load(
            Path(__file__).resolve().parent / "Model" / "model1.pkl"
        )
        logger.info(f"Model loaded: {type(model).__name__}")
    except FileNotFoundError:
        logger.error("model1.pkl not found")
        raise
    yield
    logger.info("Server shutting down.")


# ── App ────────────────────────────────────────────────────────────────────
app = FastAPI(title="PhishOps API", version="1.0.0", lifespan=lifespan)

app.mount("/static", StaticFiles(directory=BASE_DIR / "web_app"), name="static")


# ── WebSocket connection manager ───────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for conn in list(self.active_connections):
            try:
                await conn.send_text(message)
            except Exception:
                self.disconnect(conn)

manager = ConnectionManager()


# ── Routes ─────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": model is not None}


@app.get("/")
async def home():
    return FileResponse(BASE_DIR / "web_app" / "index.html")


@app.websocket("/ws/feed")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.post("/DnsRec")
async def dns(req: AnalyzeRequest):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    res = await asyncio.to_thread(dns_rec, url)
    return res


@app.post("/clear_history")
async def clear_session_history():
    global url_history
    url_history = []
    return {"status": "cleared"}


@app.post("/analyze")
async def analyze(req: AnalyzeRequest, request: Request):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    scan_id = str(uuid.uuid4())

    # Screenshots folder lives inside web_app so StaticFiles can serve it
    screenshots_dir = BASE_DIR / "web_app" / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Starting scan [{scan_id}]: {url}")

    # ── A: Call playwright microservice (HTTP, not docker run) ─────────────
    features       = None
    screenshot_url = "/static/placeholder.png"
    try:
        async with httpx.AsyncClient(timeout=90) as client:
            # First check the service is alive
            try:
                await client.get(f"{PLAYWRIGHT_URL}/health")
            except Exception:
                raise Exception(
                    f"Playwright service unreachable at {PLAYWRIGHT_URL}. "
                    "Is the playwright container running?"
                )

            resp = await client.post(
                f"{PLAYWRIGHT_URL}/scan",
                json={"url": url, "scan_id": scan_id},
            )
            resp.raise_for_status()
            data = resp.json()

        if "error" in data:
            raise Exception(f"Scanner error: {data['error']}")

        # Save screenshot from base64 — no shared volume needed
        if data.get("screenshot_b64"):
            fname    = f"scan_{scan_id}.png"
            dest_img = screenshots_dir / fname
            dest_img.write_bytes(base64.b64decode(data.pop("screenshot_b64")))
            screenshot_url = f"/static/screenshots/{fname}"
            logger.info(f"Screenshot saved → {screenshot_url}")
        else:
            data.pop("screenshot_b64", None)
            logger.warning("Playwright returned no screenshot")

        features = data

    except httpx.HTTPStatusError as e:
        logger.error(f"Playwright service HTTP error: {e.response.status_code} — {e.response.text}")
        raise HTTPException(
            status_code=500,
            detail=f"Feature extraction failed: {e.response.text}"
        )
    except Exception as e:
        logger.error(f"Feature extraction failed: {e}")
        raise HTTPException(status_code=500, detail=f"Feature extraction failed: {str(e)}")

    # ── B: ML prediction ───────────────────────────────────────────────────
    try:
        numeric = {k: v for k, v in features.items() if k not in DROPPED_COLS}
        df      = pd.DataFrame([numeric])[feature_order]
        result  = await asyncio.to_thread(predict_url, df)
    except Exception as e:
        logger.error(f"Model prediction failed: {e}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

    # ── C: DNS (non-fatal) ─────────────────────────────────────────────────
    try:
        dns_report = await asyncio.to_thread(dns_rec, url)
    except Exception as e:
        logger.warning(f"DNS lookup failed (non-fatal): {e}")
        dns_report = {}

    # ── D: Threat event (non-fatal) ────────────────────────────────────────
    try:
        ml_score = (
            result["probability"]
            if result["prediction"] == "phishing"
            else (1 - result["probability"])
        )
        event = await asyncio.to_thread(build_threat_event, url, ml_score, dns_report)
    except Exception as e:
        logger.warning(f"build_threat_event failed (non-fatal): {e}")
        event = {}

    # ── E: Final response ──────────────────────────────────────────────────
    response = {
        **event,
        "prediction":   result["prediction"],
        "probability":  result["probability"],
        "top_features": result.get("top_features", {}),
        "screenshot":   screenshot_url,
    }

    referer = request.headers.get("referer", "")
    if "threatmap.html" in referer:
        url_history.append(url)
        print(url_history)

    ui_status = "MALICIOUS" if result["prediction"] == "phishing" else "CLEAN"
    await manager.broadcast(json.dumps({
        "status": ui_status,
        "url":    url,
        "time":   datetime.now().strftime("%H:%M:%S"),
    }))

    logger.info(
        f"Scan complete [{scan_id}]: {result['prediction']} ({result['probability']:.2%})"
    )
    return response


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000)