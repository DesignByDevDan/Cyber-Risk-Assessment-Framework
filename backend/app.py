from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet
from pymongo import MongoClient
from sklearn.ensemble import RandomForestRegressor
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
import os
import pandas as pd
import numpy as np
import nmap

app = Flask(__name__)

# CORS configuration
CORS(app, resources={r"/*": {
    "origins": "http://localhost:3000",
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"]
}})
# Dynamically generate a Fernet encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Log the key for debugging purposes (remove this in production!)
print(f"Generated Fernet Key: {key.decode()}")

# MongoDB Configuration
client = MongoClient("mongodb://localhost:27017/")
db = client["risk_framework"]
assessments_collection = db["assessments"]
scans_collection = db["scans"]

# Load environment variables from .env file
load_dotenv()

# JWT Configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
jwt = JWTManager(app)

# User database (temporary; replace with MongoDB in production)
users = {}

@app.route('/')
def home():
    return jsonify({"message": "Risk Assessment Framework Backend is running."})

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Invalid input. Provide 'username' and 'password'."}), 400

    username = data['username']
    password = data['password']

    if username in users:
        return jsonify({"error": "User already exists"}), 400

    users[username] = password
    return jsonify({"message": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Invalid input. Provide 'username' and 'password'."}), 400

    username = data['username']
    password = data['password']

    if username not in users or users[username] != password:
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=username)
    return jsonify({"access_token": access_token}), 200

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Welcome {current_user}!"}), 200

@app.route('/assess-risk', methods=['POST'])
@jwt_required()
def assess_risk():
    data = request.json
    if not data or "risk_factors" not in data:
        return jsonify({"error": "Invalid input. Please include 'risk_factors'."}), 400

    risk_factors = data.get("risk_factors", [])
    recommendations = []
    total_severity = 0

    for factor in risk_factors:
        severity = factor.get("severity", 0)
        name = factor.get("name", "Unknown Risk")
        total_severity += severity

        if severity > 7:
            recommendations.append(f"Critical: Address {name} immediately.")
        elif severity > 5:
            recommendations.append(f"High: Consider mitigating {name} soon.")
        else:
            recommendations.append(f"Low: Monitor {name} over time.")

    average_severity = total_severity / len(risk_factors) if risk_factors else 0
    risk_score = round(average_severity, 2)

    # Save to MongoDB
    assessment_data = {
        "risk_factors": risk_factors,
        "risk_score": risk_score,
        "recommendations": recommendations
    }
    assessments_collection.insert_one(assessment_data)

    return jsonify({
        "risk_score": risk_score,
        "message": "Assessment complete",
        "recommendations": recommendations
    })

@app.route('/check-compliance', methods=['POST'])
@jwt_required()
def check_compliance():
    data = request.json
    if not data or "compliance_type" not in data or "risk_factors" not in data:
        return jsonify({"error": "Invalid input. Please include 'compliance_type' and 'risk_factors'."}), 400

    compliance_type = data["compliance_type"]
    risk_factors = data["risk_factors"]
    non_compliant_factors = []

    # Simulated compliance rules
    rules = {
        "ISO 27001": ["Weak Encryption", "Unpatched System"],
        "HIPAA": ["Outdated Software", "Data Breach"],
        "PCI DSS": ["Weak Encryption", "Unsecured Network"]
    }

    for factor in risk_factors:
        if factor["name"] in rules.get(compliance_type, []):
            non_compliant_factors.append(factor["name"])

    return jsonify({
        "compliance_type": compliance_type,
        "non_compliant_factors": non_compliant_factors,
        "message": f"Checked against {compliance_type} compliance."
    })

@app.route('/encrypt', methods=['POST'])
@jwt_required()
def encrypt_data():
    data = request.json
    if not data or "text" not in data:
        return jsonify({"error": "Invalid input. Please include 'text'."}), 400

    plaintext = data["text"].encode()
    encrypted_text = cipher_suite.encrypt(plaintext).decode()
    return jsonify({"encrypted_text": encrypted_text})

@app.route('/decrypt', methods=['POST'])
@jwt_required()
def decrypt_data():
    data = request.json
    if not data or "encrypted_text" not in data:
        return jsonify({"error": "Invalid input. Please include 'encrypted_text'."}), 400

    encrypted_text = data["encrypted_text"].encode()
    try:
        decrypted_text = cipher_suite.decrypt(encrypted_text).decode()
        return jsonify({"decrypted_text": decrypted_text})
    except Exception as e:
        return jsonify({"error": "Decryption failed. Invalid encrypted text."}), 400

@app.route('/scan-network', methods=['POST'])
@jwt_required()
def scan_network():
    data = request.json
    if not data or "target" not in data:
        return jsonify({"error": "Invalid input. Please include 'target'."}), 400

    target = data["target"]
    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=target, arguments='-sV')
        scan_results = []
        for host in scanner.all_hosts():
            host_info = {
                "host": host,
                "status": scanner[host].state(),
                "ports": []
            }
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    port_info = {
                        "port": port,
                        "service": scanner[host][proto][port]['name'],
                        "state": scanner[host][proto][port]['state']
                    }
                    host_info["ports"].append(port_info)
            scan_results.append(host_info)

        scans_collection.insert_one({"target": target, "results": scan_results})

        return jsonify({"results": scan_results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def train_model():
    data = list(assessments_collection.find())
    if not data:
        return None
    df = pd.DataFrame(data)
    X = df["risk_factors"].apply(lambda x: [factor["severity"] for factor in x]).values
    y = df["risk_score"].values
    model = RandomForestRegressor()
    model.fit(np.array(X.tolist()), y)
    return model

model = train_model()

@app.route('/predict-risk', methods=['POST'])
@jwt_required()
def predict_risk():
    data = request.json
    if not data or "risk_factors" not in data:
        return jsonify({"error": "Invalid input. Please include 'risk_factors'."}), 400

    if model is None:
        return jsonify({"error": "Model not trained yet. Add historical data."}), 400

    X = np.array([factor["severity"] for factor in data["risk_factors"]]).reshape(1, -1)
    predicted_risk = model.predict(X)[0]
    return jsonify({"predicted_risk_score": round(predicted_risk, 2)})

if __name__ == "__main__":
    app.run(debug=True)
