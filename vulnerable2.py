import os
import pickle
import requests
import logging
from flask import Flask, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

@app.route("/calculate")
def calculate():
    user_math = request.args.get("expression")
    # 1. Dangerous Code Execution
    # eval() will execute arbitrary Python code passed in the URL!
    result = eval(user_math)
    return str(result)

@app.route("/load_session")
def load_session():
    cookie_data = request.cookies.get("session_data")
    # 2. Insecure Deserialization
    # pickle.loads can execute arbitrary code if the cookie is tampered with.
    # JSON should be used instead of pickle for untrusted data.
    session = pickle.loads(cookie_data.encode())
    return "Session loaded"

@app.route("/read_file")
def read_file():
    filename = request.args.get("file")
    # 3. Path Traversal
    # If the user passes "../../etc/passwd", they can read sensitive server files.
    file_path = os.path.join("/var/www/uploads", filename)
    with open(file_path, 'r') as f:
        return f.read()

@app.route("/proxy")
def fetch_image():
    target_url = request.args.get("url")
    # 4. Server-Side Request Forgery (SSRF)
    # An attacker can force the server to make requests to internal IP addresses (like 127.0.0.1 or AWS metadata servers)
    response = requests.get(target_url)
    return response.content

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    
    # 5. Sensitive Data Logging
    # Passwords should NEVER be printed or logged in plain text!
    logging.info(f"User {username} attempted to log in with password {password}")
    
    return "Login received"

if __name__ == "__main__":
    app.run(debug=True)
