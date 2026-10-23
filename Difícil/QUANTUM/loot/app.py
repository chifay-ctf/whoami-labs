from flask import Flask, request, jsonify
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
SECRET_KEY = "QuantumAPISecretKey2024_WEAK"

users = {
    1: {"id": 1, "username": "researcher", "role": "user"},
    2: {"id": 2, "username": "aidev", "role": "developer"},
    3: {"id": 3, "username": "sysadmin", "role": "admin"}
}

@app.route('/')
def index():
    return jsonify({
        "service": "QuantumAI API v1.0",
        "endpoints": ["/auth", "/user/<id>", "/data", "/admin"]
    })

@app.route('/auth', methods=['POST'])
def auth():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if username == "researcher" and password == "Quant0mR3s34rch":
        token = jwt.encode({
            'user_id': 1,
            'username': username,
            'role': 'user',
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, SECRET_KEY, algorithm='HS256')
        return jsonify({"token": token})
    
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/user/<int:user_id>')
def get_user(user_id):
    if user_id in users:
        return jsonify(users[user_id])
    return jsonify({"error": "User not found"}), 404

@app.route('/data')
def get_data():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({
            "status": "success",
            "data": "Research data placeholder"
        })
    except:
        return jsonify({"error": "Invalid token"}), 401

@app.route('/admin')
def admin():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if payload.get('role') == 'admin':
            return jsonify({
                "status": "admin_access",
                "message": "Admin panel access granted"
            })
        return jsonify({"error": "Forbidden"}), 403
    except:
        return jsonify({"error": "Invalid token"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

