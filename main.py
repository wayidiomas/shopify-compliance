from fastapi import FastAPI, Request, HTTPException
import hmac
import hashlib
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

SHOPIFY_SECRET = os.getenv("SHOPIFY_SECRET")

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
