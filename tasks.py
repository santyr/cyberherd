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

def serialize_event(event):
    return json.dumps(event, sort_keys=True)

def sign_event(event, private_key_hex):
    serialized_event = serialize_event(event)
    event_hash = hashlib.sha256(serialized_event.encode('utf-8')).digest()
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    signature = sk.sign_deterministic(event_hash)
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    return signature_b64

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
                
async def get_npub_address(    
    pubkey: str
) -> Optional[str]: 

    print("trying to get npub: ", pubkey)
    uri = f"ws://localhost:{settings.port}/nostrclient/api/v1/{relay_endpoint}"
    jsonOb = ''

    # TODO utilize a try except and find out why websocket is not connecting
    async with websockets.connect(uri) as websocket:
    #websocket = websockets.connect(uri)
        req = '["REQ", "a",  {"kinds": [0], "limit": 10, "authors": ["'+ pubkey +'"]} ]'
        ''' send req to websocket and print response'''
        await websocket.send(req)                    
        greeting = await websocket.recv()
        output = json.loads(greeting)
        jsonOb = json.loads(output[2]['content'])

    #npubWallet06 = ''
    #npubWallet16 = ''
    npubWallet = ''                    
    if "lud16" in jsonOb and npubWallet == '':
        logger.info("we got a lud16: ", jsonOb["lud16"])
        if len(jsonOb["lud16"]) > 1:
            npubWallet = jsonOb["lud16"]
    #if "lud06" in jsonOb:
    #    logger.info("we got a lud06: ", jsonOb["lud06"])
    #    if len(jsonOb["lud06"]) > 1:
    #        npubWallet = jsonOb["lud06"]

    if npubWallet == '':
        print("Failed to get npub wallet")

    return npubWallet

async def get_lnurl_invoice(payoraddress, wallet_id, amount_msat, memo) -> Optional[str]:
    from lnbits.core.views.api import api_lnurlscan
    data = await api_lnurlscan(payoraddress)
    rounded_amount = floor(amount_msat / 1000) * 1000

    if not (data.get("minSendable") <= abs(rounded_amount) <= data.get("maxSendable")):
        logger.error(f"Amount {rounded_amount} is out of bounds (min: {data.get('minSendable')}, max: {data.get('maxSendable')})")
        return None

    if data.get("allowNostr") and data.get("nostrPubkey"):
        relays = ['wss://nostr-pub.wellorder.net', 'wss://relay.damus.io', 'wss://relay.primal.net'] #TODO: set from UI, add to DB
        event = {
            "kind": 9734,
            "content": memo,
            "pubkey": "PUBKEY",  # Sender's pubkey #TODO: set From user split address from UI, add to DB  do this by setting a default lud16 address that is associated with a Nostr key. api_lnurlscan(payoraddress) returns that)
            "created_at": round(time.time()),
            "tags": [
                ["relays", *relays],
                ["amount", str(rounded_amount)],
                ["p", data.get("nostrPubkey")],
            ],
        }

        event_json = json.dumps(event)
        signed_event = sign_event(event_json, "PRIVATE_KEY")  # Signing the event #TODO: set PRIVATE_KEY from UI, add to DB. Double check that the data format is correct. Probably needs to be added to event_json

        query_params = {
            "amount": rounded_amount,
            "nostr": signed_event,  # Include the event in the request  likely need to change to event_data (see TODO above)
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    data["callback"],  # The LNURL callback URL.  This request returns the invoice.
                    params=query_params,
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

