from fastapi import FastAPI, Request, HTTPException
import hmac
import hashlib
import os
from dotenv import load_dotenv
import logging

load_dotenv()

app = FastAPI()

SHOPIFY_SECRET = os.getenv("SHOPIFY_SECRET")

# Configurar o logger
logging.basicConfig(level=logging.INFO)

def verify_hmac(body: bytes, hmac_received: str) -> bool:
    """
    Verifica se o HMAC recebido é válido comparando com o HMAC gerado localmente.
    """
    # Gera o HMAC localmente usando SHA256
    generated_hmac = hmac.new(SHOPIFY_SECRET.encode('utf-8'), body, hashlib.sha256).hexdigest()

    # Compara o HMAC gerado com o HMAC recebido
    return hmac.compare_digest(generated_hmac, hmac_received)

@app.post("/webhook")
async def handle_webhook(request: Request):
    hmac_received = request.headers.get('X-Shopify-Hmac-Sha256')
    if not hmac_received:
        raise HTTPException(status_code=400, detail="Missing HMAC header")

    body = await request.body()
    
    # Verifica se o HMAC é válido
    if verify_hmac(body, hmac_received):
        logging.info("Webhook received and verified successfully.")
        return {"message": "Webhook received and verified successfully"}
    else:
        logging.error("Invalid HMAC")
        raise HTTPException(status_code=400, detail="Invalid HMAC")

@app.exception_handler(Exception)
async def validation_exception_handler(request: Request, exc: Exception):
    logging.error(f"Unhandled error: {exc}")
    return {"message": "Internal Server Error"}

@app.get("/")
async def read_root():
    return {"Hello": "World"}
