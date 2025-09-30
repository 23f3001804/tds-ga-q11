from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
import httpx
from urllib.parse import urlencode

# FastAPI app
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="your-secret-key")

# Use your Google OAuth credentials here
CLIENT_ID = "418414008335-63bkfhl271mce5n7gi9517ajebim10dg.apps.googleusercontent.com"
CLIENT_SECRET = "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"
REDIRECT_URI = "http://127.0.0.1:8000/auth/callback"
SCOPE = "openid email profile"

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


# Root route - redirect to Google login if not authenticated
@app.get("/")
def home(request: Request):
    if "id_token" not in request.session:
        return RedirectResponse("/login")
    return {"message": "You are already logged in"}


# Dedicated login route
@app.get("/login")
def login():
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


# OAuth callback
@app.get("/auth/callback")
async def auth_callback(request: Request, code: str = None):
    if not code:
        return {"error": "No code provided"}
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
    request.session["id_token"] = token_data.get("id_token")
    return RedirectResponse("/id_token")


# Route to get id_token
@app.get("/id_token")
def get_id_token(request: Request):
    id_token = request.session.get("id_token")
    if not id_token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    return {"id_token": id_token, "client_id": CLIENT_ID}


# Logout route
@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return {"message": "Logged out successfully"}
