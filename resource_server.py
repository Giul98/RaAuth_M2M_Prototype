# resource_server.py — scritture dirette su serviceRole
from flask import Flask, request, jsonify, Response
from pymongo import MongoClient
import io, csv

app = Flask(__name__)

# Mongo
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["raauth"]
services_collection = db["serviceRole"]   # dati reali

# ---------- helpers lettura ----------
def canon_cf(s) -> str:
    return (str(s) if s is not None else "").strip().upper()

def is_enabled(u: dict) -> bool:
    """Riconosce flag 'abilitato' in varianti comuni."""
    keys_true = ("abilitato", "enabled", "attivo", "active", "isEnabled")
    return any(bool(u.get(k)) for k in keys_true)

def doc_roles(doc: dict) -> list:
    """Ruoli globali al livello documento, filtrati 'checked'."""
    roles = []
    for r in (doc.get("ruoli") or []):
        desc = r.get("desc") or r.get("label") or r.get("name")
        checked = r.get("isChecked", True) or r.get("checked", False) or r.get("enabled", False)
        if desc and checked:
            roles.append(desc)
    return roles

def user_roles_from_user_array(u: dict) -> list:
    roles = []
    arr = u.get("ruoli")
    if isinstance(arr, list):
        for r in arr:
            if isinstance(r, dict):
                desc = r.get("desc") or r.get("label") or r.get("name")
                checked = r.get("isChecked", True) or r.get("checked", False) or r.get("enabled", False)
                if desc and checked:
                    roles.append(desc)
            else:
                roles.append(str(r))
    return roles

def resolve_effective_roles(u: dict, doc: dict) -> list:
    # 1) ruoli assegnati all'utente
    ur = user_roles_from_user_array(u)
    if ur:
        return ur
    # 2) boolean 'ruolo' → eredita ruoli globali
    if bool(u.get("ruolo")) is True:
        dr = doc_roles(doc)
        if dr:
            return dr
    # 3) fallback: ruoli globali
    return doc_roles(doc)

def project_visible(u: dict, doc: dict) -> dict | None:
    """Proietta un utente se abilitato e con almeno un ruolo effettivo."""
    if not is_enabled(u):
        return None
    roles = resolve_effective_roles(u, doc)
    if not roles:
        return None
    return {
        "nome": u.get("nome"),
        "cognome": u.get("cognome"),
        "CF": u.get("CF"),
        "ruoli": roles
    }

def paginate(items: list, page: int = 1, size: int = 25):
    page = max(1, int(page or 1))
    size = max(1, min(int(size or 25), 200))
    start = (page - 1) * size
    end = start + size
    return items[start:end], len(items)

def sort_users(users: list, sort: str | None):
    if not sort:
        return users
    key = sort.lstrip("-")
    reverse = sort.startswith("-")
    return sorted(users, key=lambda u: str(u.get(key, "")).lower(), reverse=reverse)

def search_match(u: dict, q: str) -> bool:
    if not q:
        return True
    q = q.strip().lower()
    return any(q in str(u.get(f, "")).lower() for f in ("nome", "cognome", "CF"))

# ---------- helpers scrittura ----------
def load_doc(app_code: str, service_code: str):
    return services_collection.find_one({"appCode": app_code, "codServizio": service_code})

def save_users_array(doc_id, new_users_array):
    services_collection.update_one(
        {"_id": doc_id},
        {"$set": {"utenti": new_users_array}}
    )

def set_enabled_field(u: dict, enabled: bool):
    """Imposta/crea il flag di abilitazione in modo tollerante allo schema."""
    # se esiste uno dei campi, aggiorna quello; altrimenti crea 'abilitato'
    for key in ("abilitato", "enabled", "attivo", "active", "isEnabled"):
        if key in u:
            u[key] = bool(enabled)
            return
    u["abilitato"] = bool(enabled)

def upsert_role_on_user(u: dict, role_code, role_desc, checked: bool):
    """Crea/aggiorna ruoli su utenti[i].ruoli[]. Non tocca i ruoli globali del documento."""
    if "ruoli" not in u or not isinstance(u["ruoli"], list):
        u["ruoli"] = []
    # trova per code o desc
    idx = None
    for i, r in enumerate(u["ruoli"]):
        if isinstance(r, dict):
            if (role_code is not None and r.get("cod") == role_code) or (role_desc and (r.get("desc") == role_desc or r.get("label") == role_desc)):
                idx = i
                break
        elif isinstance(r, str) and role_desc and r == role_desc:
            idx = i
            break
    payload = {"cod": role_code, "desc": role_desc, "isChecked": bool(checked)}
    if idx is None:
        u["ruoli"].append(payload)
    else:
        # merge: preserva 'cod' e 'desc' se mancano in input
        existing = u["ruoli"][idx] if isinstance(u["ruoli"][idx], dict) else {"desc": u["ruoli"][idx]}
        existing["cod"] = existing.get("cod", role_code)
        existing["desc"] = existing.get("desc") or role_desc
        existing["isChecked"] = bool(checked)
        u["ruoli"][idx] = existing

# ---------- endpoint ----------
@app.route("/data", methods=["POST"])
def protected_data():
    body = request.get_json(silent=True) or {}
    claims = body.get("claims", {})
    action = body.get("action")
    app_code = str(body.get("appCode", "")).strip()
    service_code = str(claims.get("aud", "")).strip()  # aud = codServizio
    params = body.get("params", {}) or {}

    if not action or not app_code or not service_code:
        return jsonify({"error": "Parametri mancanti"}), 400

    doc = load_doc(app_code, service_code)
    if not doc:
        return jsonify({"error": f"Servizio {service_code} per appCode {app_code} non trovato"}), 404

    raw_users = doc.get("utenti", [])
    doc_id = doc["_id"]

    # -------- READ / SEARCH / EXPORT --------
    if action in ("read", "search", "export_users"):
        q = params.get("q")
        sort = params.get("sort")           # "cognome" | "-cognome" | "nome" | "CF"
        page = params.get("page", 1)
        size = params.get("size", 25)

        visible = [p for u in raw_users if (p := project_visible(u, doc))]
        filtered = [u for u in visible if search_match(u, q)]
        sorted_users = sort_users(filtered, sort)

        if action == "export_users":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["nome", "cognome", "CF", "ruoli"])
            for u in sorted_users:
                writer.writerow([u["nome"], u["cognome"], u["CF"], "|".join(u["ruoli"])])
            csv_bytes = output.getvalue().encode("utf-8")
            return Response(
                csv_bytes,
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename=users_{app_code}_{service_code}.csv"}
            )

        page_items, total = paginate(sorted_users, page=page, size=size)
        return jsonify({
            "message": f"Utenti del servizio {service_code}",
            "descrizioneApp": doc.get("descrizioneApp"),
            "count": total,
            "page": int(page),
            "size": int(size),
            "users": page_items,
            "validated_claims": claims
        })

    # -------- GET USER --------
    elif action == "get_user":
        cf = canon_cf(params.get("cf"))
        if not cf:
            return jsonify({"error": "cf mancante"}), 400
        base = next((u for u in raw_users if canon_cf(u.get("CF")) == cf), None)
        if not base:
            return jsonify({"error": f"Utente {cf} non trovato"}), 404
        proj = project_visible(base, doc)
        return (jsonify({"user": proj}), 200) if proj else (jsonify({"error": "Utente non abilitato o senza ruoli"}), 403)

    # -------- WRITE DIRETTE: DISABLE / ENABLE / ASSIGN / REMOVE --------
    elif action in ("disable_user", "enable_user", "assign_role", "remove_role"):
        cf = canon_cf(params.get("cf"))
        if not cf:
            return jsonify({"error": "cf mancante"}), 400

        # trova utente
        idx = None
        for i, u in enumerate(raw_users):
            if canon_cf(u.get("CF")) == cf:
                idx = i
                break
        if idx is None:
            return jsonify({"error": f"Utente {cf} non trovato"}), 404

        # copia e modifica
        users_new = list(raw_users)
        u = dict(users_new[idx])

        if action == "disable_user":
            set_enabled_field(u, False)
        elif action == "enable_user":
            set_enabled_field(u, True)
        else:
            role_code = params.get("role_code")
            role_desc = params.get("role_desc")
            if not role_desc and role_code is None:
                return jsonify({"error": "role_desc o role_code richiesto"}), 400
            checked = (action == "assign_role")
            upsert_role_on_user(u, role_code, role_desc, checked)

        users_new[idx] = u
        save_users_array(doc_id, users_new)
        return jsonify({"result": "ok", "action": action, "CF": cf})

    else:
        return jsonify({"error": f"Azione non gestita: {action}"}), 400

if __name__ == "__main__":
    app.run(port=6000)
