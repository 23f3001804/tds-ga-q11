from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
import httpx
import os
from urllib.parse import urlencode
from google.oauth2 import id_token
from google.auth.transport import requests as grequests

# Load secrets from environment variables (DO NOT hardcode in production!)
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "your-client-id")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "your-client-secret")
REDIRECT_URI = "http://127.0.0.1:8000/auth/callback"
SCOPE = "openid email profile"

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="your-secret-key")  # use a secure random key!


@app.get("/")
def home(request: Request):
    """Home page: redirect to Google if not logged in"""
    if "id_token" not in request.session:
        params = {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": SCOPE,
            "access_type": "offline",
            "prompt": "select_account"
        }
        url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
        return RedirectResponse(url)
    return {"message": "You are logged in"}


@app.get("/auth/callback")
async def auth_callback(request: Request, code: str = None):
    """Handle OAuth2 callback from Google"""
    if not code:
        return JSONResponse({"error": "No code provided"}, status_code=400)

    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    async with httpx.AsyncClient() as client:
        r = await client.post(GOOGLE_TOKEN_URL, data=data)
        token_data = r.json()

    if "error" in token_data:
        return JSONResponse(token_data, status_code=400)

    # Save only the id_token in session
    request.session["id_token"] = token_data.get("id_token")

    return RedirectResponse("/id_token")


@app.get("/id_token")
def get_id_token(request: Request):
    """Return the stored ID token and user info if valid"""
    id_token_value = request.session.get("id_token")
    if not id_token_value:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    try:
        # Verify the token with Google
        idinfo = id_token.verify_oauth2_token(
            id_token_value,
            grequests.Request(),
            CLIENT_ID
        )
    except Exception:
        return JSONResponse({"error": "Invalid ID token"}, status_code=401)

    return {
        "id_token": id_token_value,
        "user_info": {
            "email": idinfo.get("email"),
            "name": idinfo.get("name"),
            "picture": idinfo.get("picture")
        }
    }
