from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from .config import settings, validate_startup_config
from .database import Base, engine
from .routers import auth_routes, emails

validate_startup_config()

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="MailGuard - Email Threat Forensics API",
    description="Analyst-facing API: upload .eml files, get a fused fraud "
                 "score, a step-by-step explainable flowchart, and origin geolocation.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Baseline security headers - defense in depth, not a substitute for
    running this behind HTTPS/a reverse proxy in production."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response


app.add_middleware(SecurityHeadersMiddleware)

app.include_router(auth_routes.router)
app.include_router(emails.router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/health/nlp")
def health_nlp():
    """Reports whether the TF-IDF/LogReg model trained successfully and
    whether the transformer model loaded - handy to hit right after
    startup to confirm the NLP engine is ready before your demo."""
    from .modules import nlp_engine

    return nlp_engine.model_status()
