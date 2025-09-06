import requests

scope = "125457"   # servizio di destinazione
action = "read"    # azione concessa in clients.allowed_actions[scope]
client_id = "microA"

# 1) token
res = requests.post("http://127.0.0.1:5000/token", json={
    "client_id": client_id,
    "client_secret": "12345",
    "scope": scope
})
res.raise_for_status()
token = res.json()["access_token"]
print("Token ottenuto:", token)

# 2) chiamata a RAAuth
headers = {"Authorization": f"Bearer {token}"}
res2 = requests.post("http://127.0.0.1:7000/gateway", headers=headers, json={
    "service": scope,
    "action": action
})
print("Risposta da RAAuth:")
print(res2.json())
