from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
import hmac
import hashlib
import os
from dotenv import load_dotenv
import base64
import requests
import secrets
import logging

load_dotenv()

app = FastAPI()

SHOPIFY_SECRET = os.getenv("SHOPIFY_SECRET")
SHOPIFY_API_KEY = os.getenv("SHOPIFY_API_KEY")
REDIRECT_URI = 'https://shopify-compliance.onrender.com/auth/callback'
SCOPES = 'read_all_orders,read_orders,write_orders'
BUBBLE_API_URL = 'https://go.smartseller.tech/api/1.1/obj/shop-auth'  # URL do seu endpoint no Bubble

# Configurar o logger
logging.basicConfig(level=logging.INFO)

@app.get("/auth")
async def auth(request: Request):
    shop = request.query_params.get('shop')
    if shop:
        state = secrets.token_urlsafe(16)  # Gera um valor state aleatório
        auth_url = f"https://{shop}.myshopify.com/admin/oauth/authorize?client_id={SHOPIFY_API_KEY}&scope={SCOPES}&redirect_uri={REDIRECT_URI}&state={state}&response_type=code"
        logging.info(f"Redirecting to: {auth_url}")
        return RedirectResponse(auth_url)
    else:
        raise HTTPException(status_code=400, detail="Missing shop parameter")

@app.get("/auth/callback")
async def auth_callback(request: Request):
    code = request.query_params.get('code')
    shop = request.query_params.get('shop')
    if code and shop:
        try:
            data = {
                'client_id': SHOPIFY_API_KEY,
                'client_secret': SHOPIFY_SECRET,
                'code': code
            }
            access_token_response = requests.post(f"https://{shop}.myshopify.com/admin/oauth/access_token", data=data)
            access_token_response.raise_for_status()
            access_token = access_token_response.json().get('access_token')
            if access_token:
                # Enviar o nome da loja e o token de acesso para o Bubble
                bubble_response = requests.post(
                    BUBBLE_API_URL,
                    json={
                        'shop': shop,
                        'token': access_token
                    },
                    headers={
                        'Content-Type': 'application/json'
                    }
                )
                bubble_response.raise_for_status()
                logging.info(f"Shop: {shop}, Token: {access_token}")
                return {"message": "Authentication successful", "access_token": access_token}
            else:
                logging.error("Failed to obtain access token")
                raise HTTPException(status_code=400, detail="Failed to obtain access token")
        except requests.exceptions.RequestException as e:
            logging.error(f"HTTP request failed: {e}")
            raise HTTPException(status_code=500, detail="Failed to communicate with Shopify API")
    else:
        raise HTTPException(status_code=400, detail="Missing code or shop parameters")

@app.exception_handler(Exception)
async def validation_exception_handler(request: Request, exc: Exception):
    logging.error(f"Unhandled error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"message": "Internal Server Error"},
    )

@app.get("/")
async def read_root():
    return {"Hello": "World"}
