import requests
from pprint import pprint


# Configuration parameters for the Machine to Machine (M2M)
# authentication prototype using OAuth 2.0 Client Credentials.

client_id = "microD"
client_secret = "zxcvb"
scope = "https://microD.regione.abruzzo.it"   # Scope identifies the client as registered at the Identity Provider (IdP)
service = "125459"                            # Service code representing the resource to be accessed
base_auth_url = "http://127.0.0.1:5000/token"
base_gateway_url = "http://127.0.0.1:7000/gateway"


# 1. TOKEN REQUEST (Client Credentials Grant)
# The client authenticates itself to the Authorization Server
# by providing its client_id, client_secret, and scope.

res = requests.post(base_auth_url, json={
    "client_id": client_id,
    "client_secret": client_secret,
    "scope": scope
})

print("STATUS:", res.status_code)
print("BODY:", res.text)

# If the token request fails, terminate execution
if res.status_code != 200 or "access_token" not in res.json():
    print("Error: token request failed. Execution stopped.")
    exit(1)

token = res.json()["access_token"]
print("\nAccess token received:\n", token, "\n")

headers = {"Authorization": f"Bearer {token}"}


# 2. READ OPERATION
# The client requests the reading of a specific field in the
# service document stored in MongoDB, through the RAAuth gateway.

print("---- READ ----")
res2 = requests.post(base_gateway_url, headers=headers, json={
    "service": service,
    "action": "read",
    "field": "utenti.0.ruoli.0.gruppo.0.codice"   # Example of a nested path within the JSON document
})
pprint(res2.json())


# 3. UPDATE OPERATION
# The client performs an update operation on a document field.
# This request is forwarded by RAAuth to the Resource Server,
# which updates the MongoDB record accordingly.

print("\n---- UPDATE ----")
res3 = requests.post(base_gateway_url, headers=headers, json={
    "service": service,
    "action": "update",
    "data": {"services.0.nome": "Nome Servizio"}  # Example of a key-value update
})
pprint(res3.json())


# 4. ADD OPERATION
# The client adds a new element to an array field in the document.
# This demonstrates a write-type operation on the data layer.

print("\n---- ADD ----")
res4 = requests.post(base_gateway_url, headers=headers, json={
    "service": service,
    "action": "add",
    "array": "services",    # Name of the array within the service document
    "data": {
        "service": "servizioTest",
        "port": "111",
        "isExternal": True
    }
})
pprint(res4.json())
