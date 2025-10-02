import requests
from pprint import pprint

scope = "125459"   # codServizio
client_id = "microD"

# 1) TOKEN
res = requests.post("http://127.0.0.1:5000/token", json={
    "client_id": client_id,
    "client_secret": "zxcvb",
    "scope": scope
})

print("STATUS:", res.status_code)
print("BODY:", res.text)

token = res.json()["access_token"]

print("Il Token ricevuto è:", token);

headers = {"Authorization": f"Bearer {token}"}

#2) LETTURA INTERO SERVIZIO
res2 = requests.post("http://127.0.0.1:7000/gateway", headers=headers, json={
    "service": scope,
    "action": "read",
    "field" : "utenti.0.ruoli.0.gruppo.0.codice"
})
print("READ:")
pprint(res2.json())


# 3) AGGIORNAMENTO (Anche per aggiungere elementi si fa con update)
res3 = requests.post("http://127.0.0.1:7000/gateway", headers=headers, json={
    "service": scope,
    "action": "update",
    "data": {"test": "test"}
})
print("UPDATE:")
pprint(res3.json())


# 4) AGGIUNTA ELEMENTO AD ARRAY
res4 = requests.post("http://127.0.0.1:7000/gateway", headers=headers, json={
    "service": scope,
    "action": "add",
    "array": "services",    # nome array dentro il JSON del servizio
    "data": {"service": "servizioTest", "port": "111", "isExternal": "true"}
})
print("ADD:")
pprint(res4.json())
