import requests

# 1. Richiesta token con service target (codServizio)
res = requests.post("http://127.0.0.1:5000/token",
    json={
        "client_id": "microA",
        "client_secret": "12345",
        "service": "125455"   # qui il codServizio
    }
)
token = res.json().get("access_token")
print("Token ottenuto:", token)

# 2. Chiamata a RAAuth
headers = {
    "Authorization": f"Bearer {token}",
    "AppId": "000011"
}
res2 = requests.post("http://127.0.0.1:7000/gateway", headers=headers, json={"service": "125455"})
print(res2.json())
