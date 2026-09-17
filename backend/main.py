import os
import pathlib
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from .router import router as api_router
from .database_seed import seed_database

app = FastAPI(
    title="AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform",
    description="Enterprise-grade SOC and Digital Forensics platform for email threat detection, correlation, and explainable investigation.",
    version="2.4.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Router
app.include_router(api_router, prefix="/api")

# Determine Frontend Build Directory
BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
ASSETS_DIR = FRONTEND_DIST / "assets"

# Seed Database on startup
@app.on_event("startup")
def on_startup():
    try:
        seed_database()
        print(">> Database seeded successfully with enterprise demo cases.")
    except Exception as e:
        print(f">> Database seed warning: {e}")

# Mount frontend assets if directory exists
if ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")

# Catch-all route to serve the React SPA index.html for client-side routing
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    # If requesting an API route that didn't match, return 404 JSON
    if full_path.startswith("api/"):
        return JSONResponse(status_code=404, content={"detail": "API endpoint not found"})
    
    # Check if a direct file in frontend/dist was requested (e.g., favicon.ico, logo.png)
    target_file = FRONTEND_DIST / full_path
    if full_path and target_file.is_file():
        return FileResponse(str(target_file))
    
    # Fallback to SPA index.html
    index_file = FRONTEND_DIST / "index.html"
    if index_file.is_file():
        return FileResponse(str(index_file))
    
    return JSONResponse(
        status_code=200,
        content={"message": "FastAPI is running. Please build the frontend (`npm run build` in frontend/) to view the web platform."}
    )

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
