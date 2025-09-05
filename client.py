import requests

# 1. Richiesta token dall'Authorization Server
res = requests.post("http://127.0.0.1:5000/token",
    json={
        "client_id": "microA",
        "client_secret": "12345",
        "scope": "125457"   # chiede accesso al servizio con codServizio=125455
    }
)

if res.status_code != 200:
    print("Errore nella richiesta del token:", res.status_code, res.text)
    exit(1)

token = res.json().get("access_token")
print("Token ottenuto:", token)

# 2. Chiamata al gateway RAAuth
headers = {
    "Authorization": f"Bearer {token}",
    "AppId": "000019"  # deve corrispondere a un appCode censito in Mongo
}
res2 = requests.post("http://127.0.0.1:7000/gateway", headers=headers, json={"service": "125457"})

print("Risposta da RAAuth:")
print(res2.json())
