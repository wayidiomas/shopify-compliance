from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse
import hmac
import hashlib
import os
from dotenv import load_dotenv
import base64
import requests
from typing import Optional

load_dotenv()

app = FastAPI()

SHOPIFY_SECRET = os.getenv("SHOPIFY_SECRET")
SHOPIFY_API_KEY = os.getenv("SHOPIFY_API_KEY")
REDIRECT_URI = 'https://shopify-compliance.onrender.com/auth/callback'
SCOPES = 'read_all_orders,read_orders,write_orders'

def generate_hmac(params: dict, secret: str) -> str:
    message = '&'.join([f"{key}={value}" for key, value in sorted(params.items())])
    return base64.b64encode(hmac.new(secret.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).digest()).decode()

@app.get("/auth")
async def auth(request: Request):
    shop = request.query_params.get('shop')
    if shop:
        state = "random_state_string"  # Pode ser um valor gerado dinamicamente
        auth_url = f"https://{shop}/admin/oauth/authorize?client_id={SHOPIFY_API_KEY}&scope={SCOPES}&redirect_uri={REDIRECT_URI}&state={state}"
        return RedirectResponse(auth_url)
    else:
        raise HTTPException(status_code=400, detail="Missing shop parameter")

@app.get("/auth/callback")
async def auth_callback(request: Request):
    code = request.query_params.get('code')
    shop = request.query_params.get('shop')
    if code and shop:
        data = {
            'client_id': SHOPIFY_API_KEY,
            'client_secret': SHOPIFY_SECRET,
            'code': code
        }
        access_token_response = requests.post(f"https://{shop}/admin/oauth/access_token", data=data)
        access_token_response.raise_for_status()
        access_token = access_token_response.json().get('access_token')
        if access_token:
            # Armazene o token de acesso de maneira segura (e.g., em um banco de dados)
            return {"message": "Authentication successful", "access_token": access_token}
        else:
            raise HTTPException(status_code=400, detail="Failed to obtain access token")
    else:
        raise HTTPException(status_code=400, detail="Missing code or shop parameters")

@app.get("/")
async def read_root():
    return {"Hello": "World"}
