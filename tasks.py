import asyncio
import json
from math import floor
from typing import Optional
import bech32
import websockets
import httpx
import time
from loguru import logger
from ecdsa import SECP256k1, SigningKey
import hashlib
import base64

from lnbits import bolt11
from lnbits.core.crud import get_standalone_payment
from lnbits.core.models import Payment
from lnbits.core.services import create_invoice, fee_reserve, pay_invoice
from lnbits.helpers import get_current_extension_name
from lnbits.app import settings
from lnbits.tasks import register_invoice_listener

from .crud import get_targets

def remove_id_and_sig(event: dict) -> dict:                                                                                                                 
    return {k: v for k, v in event.items() if k not in ['id', 'sig']}

def serialize_event(event: dict) -> bytes:                                                                                                                  
    return json.dumps([                                                                                                                                     
        0,                                                                                                                                                  
        event['pubkey'],                                                                                                                                    
        event['created_at'],                                                                                                                                
        event['kind'],                                                                                                                                      
        event.get('tags', []),                                                                                                                              
        event.get('content', '')                                                                                                                            
    ], separators=(',', ':'), ensure_ascii=False).encode('utf-8')                                                                                           

def compute_event_hash(serialized_event: bytes) -> bytes:                                                                                                   
    return hashlib.sha256(serialized_event).digest()

def sign_event_hash(event_hash: bytes, private_key_hex: str) -> str:                                                                                        
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)                                                                            
    signature = sk.sign_deterministic(event_hash)    
    return signature.hex()

def update_event_with_id_and_sig(event: dict, event_hash: bytes, signature_hex: str) -> dict:                                                               
    event['id'] = event_hash.hex()                                                                                                                          
    event['sig'] = signature_hex                                                                                                                            
    return event

async def sign_event(event: dict, private_key_hex: str) -> dict:                                                                                            
    event_to_sign = remove_id_and_sig(event)                                                                                                                
    serialized_event = serialize_event(event_to_sign)                                                                                                       
    event_hash = compute_event_hash(serialized_event)                                                                                                       
    signature_hex = sign_event_hash(event_hash, private_key_hex)                                                                                            
    signed_event = update_event_with_id_and_sig(event, event_hash, signature_hex)                                                                           
    return signed_event

async def wait_for_paid_invoices():
    invoice_queue = asyncio.Queue()
    register_invoice_listener(invoice_queue, get_current_extension_name())

    while True:
        payment = await invoice_queue.get()
        await on_invoice_paid(payment)

async def on_invoice_paid(payment: Payment) -> None:
    if payment.extra.get("tag") == "cyberherd" or payment.extra.get("splitted"):
        return

    targets = await get_targets(payment.wallet_id)
    if not targets:
        return

    total_percent = sum([target.percent for target in targets])
    if total_percent > 100:
        logger.error("cyberherd: total percent adds up to more than 100%")
        return

    logger.trace(f"cyberherd: performing split payments to {len(targets)} targets")

    for target in targets:
        if target.percent > 0:
            amount_msat = int(payment.amount * target.percent / 100)
            memo = f"CyberHerd Treats: {target.percent}% for {target.alias or target.wallet}"
            payment_request = None
            if target.wallet.find("@") >= 0 or target.wallet.find("LNURL") >= 0:
                safe_amount_msat = amount_msat - fee_reserve(amount_msat)
                payment_request = await get_lnurl_invoice(
                    target.wallet, payment.wallet_id, safe_amount_msat, memo
                )
            else:
                _, payment_request = await create_invoice(
                    wallet_id=target.wallet,
                    amount=int(amount_msat / 1000),
                    internal=True,
                    memo=memo,
                )

            extra = {**payment.extra, "tag": "cyberherd", "splitted": True}
            if payment_request:
                await pay_invoice(
                    payment_request=payment_request,
                    wallet_id=payment.wallet_id,
                    description=memo,
                    extra=extra,
                )

async def get_lnurl_invoice(payoraddress, wallet_id, amount_msat, memo) -> Optional[str]:
    from lnbits.core.views.api import api_lnurlscan
    data = await api_lnurlscan(payoraddress)
    rounded_amount = floor(amount_msat / 1000) * 1000

	if not (data.get("minSendable") <= abs(rounded_amount) <= data.get('maxSendable')):
    	logger.error(f"{lud16}: amount {rounded_amount} is out of bounds (min: {data['minSendable']}, max: {data['maxSendable']})")
        return {"success": False, "message": "Amount out of bounds"}

    if data.get("allowsNostr") and data.get("nostrPubkey"):
        event_details = {
           "kind": 9734,
           "content": description or "CyberHerd Treats",
           "tags": [
               ["p", lnurl_data["nostrPubkey"]]
            ],
            "pubkey": '669ebbcccf409ee0467a33660ae88fd17e5379e646e41d7c236ff4963f3c36b6',
            "created_at": round(datetime.now().timestamp()),
        }
        
        signed_zap_event = await sign_event(event_details, nos_sec)  # Make sure sign_event is defined correctly to sign Nostr events
        zap_event_encoded = quote(json.dumps(signed_zap_event))
        zap_url = f"{data['callback']}?amount={rounded_amount}&nostr={zap_event_encoded}"
        zap_response = await client.get(zap_url, headers=headers)
        zap_response.raise_for_status()

        invoice = zap_response.json().get('pr', None)
        return invoice

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    data["callback"],  # The LNURL callback URL.  This request returns the invoice.
                     params={"amount": rounded_amount, "comment": memo},
                    timeout=40
                )
                response.raise_for_status()
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error occurred: {e}")
                return None
            except httpx.RequestError as e:
                logger.error(f"Request error occurred: {e}")
                return None

        response_data = response.json()
        if response_data.get("status") == "ERROR":
            logger.error(f"Error from LNURL service: {response_data.get('reason')}")
            return None

        invoice = response_data.get("pr")
        
        if not invoice:
            logger.error("No invoice received in response")
            return None

        return invoice
    else:
        logger.error("LNURL does not support Nostr or missing necessary data")
        return None

