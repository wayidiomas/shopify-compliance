from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
import hmac
import hashlib
import os
from dotenv import load_dotenv
import base64
import requests

load_dotenv()

app = FastAPI()

SHOPIFY_SECRET = os.getenv("SHOPIFY_SECRET")
SHOPIFY_API_KEY = os.getenv("SHOPIFY_API_KEY")
SHOPIFY_API_SECRET = os.getenv("SHOPIFY_API_SECRET")
REDIRECT_URI = 'https://seuservico.onrender.com/auth/callback'  # Atualize para a sua URL
SCOPES = 'read_products,write_orders'

def verify_hmac(request: Request) -> bool:
    hmac_header = request.headers.get("x-shopify-hmac-sha256")
    body = request.body()
    hash = hmac.new(
        SHOPIFY_SECRET.encode("utf-8"),
        body,
        hashlib.sha256
    ).digest()
    computed_hmac = base64.b64encode(hash).decode()
    return hmac.compare_digest(computed_hmac, hmac_header)

@app.post("/webhook")
async def handle_webhook(request: Request):
    if not verify_hmac(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    data = await request.json()
    # Process the webhook data here
    print("Webhook received and verified:", data)
    return {"message": "Webhook received successfully"}

@app.get("/")
async def read_root():
    return {"Hello": "World"}

@app.get("/auth")
async def auth(request: Request):
    shop = request.query_params.get('shop')
    if shop:
        auth_url = f"https://{shop}/admin/oauth/authorize?client_id={SHOPIFY_API_KEY}&scope={SCOPES}&redirect_uri={REDIRECT_URI}&state=random_state_string"
        return RedirectResponse(auth_url)
    else:
        raise HTTPException(status_code=400, detail="Missing shop parameter")

@app.get("/auth/callback")
async def auth_callback(request: Request):
    code = request.query_params.get('code')
    shop = request.query_params.get('shop')
    if code and shop:
        access_token_response = requests.post(
            f"https://{shop}/admin/oauth/access_token",
            data={
                'client_id': SHOPIFY_API_KEY,
                'client_secret': SHOPIFY_API_SECRET,
                'code': code
            }
        )
        access_token = access_token_response.json().get('access_token')
        if access_token:
            # Store the access token securely (e.g., in a database)
            return {"message": "Authentication successful", "access_token": access_token}
        else:
            raise HTTPException(status_code=400, detail="Failed to obtain access token")
    else:
        raise HTTPException(status_code=400, detail="Missing code or shop parameters")
