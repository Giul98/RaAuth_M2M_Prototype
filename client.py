import requests

BASE = "http://127.0.0.1"
scope = "125457"
client_id = "microA"

def get_token():
    r = requests.post(f"{BASE}:5000/token", json={
        "client_id": client_id, "client_secret": "12345", "scope": scope
    })
    r.raise_for_status()
    return r.json()["access_token"]

def call(action, **params):
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    body = {"service": scope, "action": action}
    body.update(params)
    r = requests.post(f"{BASE}:7000/gateway", headers=headers, json=body)
    print(action, "->", r.status_code)
    print(r.json())

# Lettura con filtro/paging/sort
#call("read", q="ruocco", page=1, size=20, sort="cognome")
# Ricerca (alias di read)
#call("search", q="ruocco", page=1, size=10)
# Dettaglio utente
#call("get_user", cf="RCCGLI98C57A345J")
# Export CSV (scarica dal RS)
#call("export_users", q="mar", sort="-cognome")
# Scritture simulate
#call("disable_user", cf="CCCLCN65D09A345J")
#call("enable_user", cf="CCCLCN65D09A345J")
#call("get_user", cf="RCCGLI98C57A345J")   # atteso 200
#call("assign_role", cf="CCCLCN65D09A345J", role_desc="Amministratore")
#call("remove_role", cf="RCCGLI98C57A345J", role_desc="Amministratore")

#utente regionale generico