from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/data", methods=["POST"])
def protected_data():
    # Riceve la richiesta da RAAuth
    claims = request.json.get("claims", {})
    return jsonify({
        "message": "Risposta dal Resource Server",
        "received_claims": claims,
        "data": [1, 2, 3]  # esempio dati
    })

if __name__ == "__main__":
    app.run(port=6000)
