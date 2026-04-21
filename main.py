from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import analyze, alerts, pdf_report

app = FastAPI(
    title="AppGuard AI",
    description="Yellowsense presents Fake Banking & Digital Lending App Detection - RBI HaRBInger 2025",
    version="0.1.0"
)

# --- CORS MIDDLEWARE ADDED HERE ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://34.100.137.12",   # Production frontend
        "http://localhost:5173",  # Dev frontend
        "*"                       # Fallback for testing
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ----------------------------------

app.include_router(analyze.router, prefix="/api/v1", tags=["Analysis"])
app.include_router(alerts.router, prefix="/api/v1", tags=["Alerts"])
app.include_router(pdf_report.router, prefix="/api/v1", tags=["Reports"])

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "AppGuard AI",
        "version": "0.1.0"
    }