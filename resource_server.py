from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)

mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["raauth"]
services_collection = db["serviceRole"]

@app.route("/data", methods=["POST"])
def protected_data():
    body = request.get_json(silent=True) or {}
    claims = body.get("claims", {})
    action = body.get("action")
    app_code = str(body.get("appCode", "")).strip()
    service_code = str(claims.get("aud", "")).strip()

    if not action or not app_code or not service_code:
        return jsonify({"error": "Parametri mancanti"}), 400

    print(f"DEBUG RS - appCode={app_code}, codServizio={service_code}, action={action}")

    if action == "read":
        # 🔎 usa **entrambi** i campi
        service_doc = services_collection.find_one({
            "appCode": app_code,
            "codServizio": service_code
        })
        if not service_doc:
            return jsonify({"error": f"Servizio {service_code} per appCode {app_code} non trovato"}), 404

        utenti = [
            {
                "nome": u.get("nome"),
                "cognome": u.get("cognome"),
                "CF": u.get("CF"),
                "ruoli": [r.get("desc") for r in u.get("ruoli", []) if r.get("isChecked")]
            }
            for u in service_doc.get("utenti", [])
            if u.get("abilitato")
        ]

        print(f"DEBUG RS - utenti_abilitati={len(utenti)}")

        return jsonify({
            "message": f"Utenti del servizio {service_code}",
            "descrizioneApp": service_doc.get("descrizioneApp"),
            "count": len(utenti),
            "users": utenti,
            "validated_claims": claims
        })

    return jsonify({"error": "Azione non gestita"}), 400

if __name__ == "__main__":
    app.run(port=6000)
