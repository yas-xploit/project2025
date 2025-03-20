from flask import Flask, jsonify, request
import logging

app_flask = Flask(__name__)
system_metrics = {"alerts_count": 0, "files_monitored": 0}

@app_flask.route("/api/metrics", methods=["GET"])
def get_metrics():
    return jsonify(system_metrics)

@app_flask.route("/api/alert", methods=["POST"])
def receive_alert():
    data = request.json
    logging.info(f"Received alert via API: {data}")
    return jsonify({"status": "received"}), 200

def run_api():
    app_flask.run(port=5000)
