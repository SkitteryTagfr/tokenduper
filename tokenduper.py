import asyncio
import websockets
import base64
import json
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import requests

async def handshake(token, fingerprint):
    response = requests.post("https://discord.com/api/v9/users/@me/remote-auth", headers={'Authorization': token}, json={'fingerprint': fingerprint}).json() # getting handhsake token
    handshake_token = response['handshake_token']
    print(handshake_token)
    r = requests.post("https://discord.com/api/v9/users/@me/remote-auth/finish", headers={"Authorization": token}, json={'handshake_token': handshake_token}) # finishing handshake 
    print(r.text)

async def main(token):
    uri = "wss://remote-auth-gateway.discord.gg/?v=2"
    headers = {"Authorization": token, "Origin": "https://discord.com"}

    try:
        async with websockets.connect(uri, extra_headers=headers) as ws: # connecting
            print(f"Connected to Discord Remote auth gateway")

            hi = await ws.recv() #receiving hello
            print(f"Received hello: {hi}")
            pkey, privk = await genrsa() #rsa key pair getting serialized
            keyy = base64.b64encode(pkey.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode('utf-8')

            ipck = {"op": "init", "encoded_public_key": keyy} #packet
            await ws.send(json.dumps(ipck)) # sending rsa thingy
            print(f"Sent init packet: {ipck}")
            npck = await ws.recv() # receiving nonce proof
            print(f"Received nonce_proof: {npck}")
            proof = await handlen(npck, privk) # handleing nonce proof (decoding decrypting encoding)
            await ws.send(proof) # sending it back
            print("Sent nonce_proof proof to the server")
            fingerprintt = await ws.recv() # getting fingerprint
            print(fingerprintt)
            fdata = json.loads(fingerprintt)
            fingerprint = fdata.get("fingerprint", None)    
            print(fingerprint)        
            handshakee = await handshake(token, fingerprint) # using fingerprint for handshake
            print(handshakee)
            ok = await ws.recv() # receiving user infos (not important)
            print(ok)
            okk = json.loads(ok)
            encrp = okk.get("encrypted_user_payload", None)
            print(encrp)
            await decryptp(encrp, privk)
            oke = await ws.recv() # receiving login ticket
            print(oke)
            okee = json.loads(oke)
            tickett = okee.get("ticket", None)
            print(tickett)
            r = requests.post("https://discord.com/api/v9/users/@me/remote-auth/login", json={"ticket": tickett}) # using login ticket to get encrypted token
            print(r.text)
            re = json.loads(r.text)
            encrptkn = re.get("encrypted_token", None)
            print(encrptkn)
            await decryptp(encrptkn, privk) # decoding and decrypting token

    except websockets.exceptions.ConnectionClosedError as e:
        print(f"WebSocket connection closed: {e}")
async def handlen(npck, privk):
    ndata = json.loads(npck)
    print(ndata)
    encrn = base64.b64decode(ndata["encrypted_nonce"])
    print(encrn)
    decrn = privk.decrypt(
        encrn,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(decrn)

    proof = json.dumps({
        "op": "nonce_proof",
        "proof": base64.urlsafe_b64encode(hashlib.sha256(decrn).digest()).rstrip(b"=").decode(),
    })

    print(proof)
    return proof
async def decryptp(encrp, prvkey):
        payload = base64.b64decode(encrp)
        decrypted = prvkey.decrypt(
        payload,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
        print(decrypted)
        return decrypted
async def genrsa():
    privk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pkey = privk.public_key()
    return pkey, privk

if __name__ == "__main__":
    token = input("Token: ")
    asyncio.get_event_loop().run_until_complete(main(token))
