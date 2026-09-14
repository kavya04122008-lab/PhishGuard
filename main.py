from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from analyzer import analyze_email


app = FastAPI(
    title="PhishGuard API",
    description="Defensive phishing email analysis API",
    version="1.0.0",
)


# Allow the frontend to communicate with the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EmailInput(BaseModel):
    sender: str
    subject: str
    body: str = ""
    url: str = ""


@app.get("/")
def root():
    return {
        "message": "PhishGuard API is running"
    }


@app.get("/api/health")
def health_check():
    return {
        "status": "ok"
    }


@app.post("/api/analyze")
def analyze(data: EmailInput):
    result = analyze_email(
        sender=data.sender,
        subject=data.subject,
        body=data.body,
        url=data.url,
    )

    return result