# FastAPI application factory
from fastapi import FastAPI


def create_app() -> FastAPI:
    # Create and configure the FastAPI app
    app = FastAPI(title="Agentic Honeypot API")
    return app


# App instance imported by main.py
app = create_app()
