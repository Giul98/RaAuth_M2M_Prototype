import requests

res = requests.post(
    "http://127.0.0.1:5000/token",
    json={"client_id": "microA", "client_secret": "12345"},
    headers={"Content-Type": "application/json"}
)

print("Status code:", res.status_code)
print("Response text:", res.text)

if res.status_code == 200:
    token = res.json().get("access_token")
    print("Token ottenuto:", token)
    headers = {"Authorization": f"Bearer {token}"}
    res2 = requests.get("http://127.0.0.1:6000/data", headers=headers)
    print(res2.json())
