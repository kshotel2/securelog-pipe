import logging
import os
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

# 로그 디렉토리 생성
os.makedirs("logs", exist_ok=True)

# 커스텀 로거 설정
logger = logging.getLogger("access")
logger.setLevel(logging.INFO)

handler = logging.FileHandler("logs/access.log")
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)


def log_request(status_code: int):
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    ip = request.remote_addr
    method = request.method
    path = request.full_path if request.query_string else request.path
    user_agent = request.headers.get("User-Agent", "-")
    logger.info(f"{timestamp} {ip} {method} {path} {status_code} {user_agent}")


@app.route("/")
def index():
    log_request(200)
    return jsonify({"message": "Welcome to SecureLogPipe demo app"}), 200


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # 데모용 단순 인증 (절대 실사용 금지)
    if username == "admin" and password == "secret":
        log_request(200)
        return jsonify({"message": "Login successful"}), 200
    else:
        log_request(401)
        return jsonify({"message": "Invalid credentials"}), 401


@app.route("/search")
def search():
    query = request.args.get("q", "")
    log_request(200)
    # 실제 DB 쿼리 없이 에코만 반환 (데모용)
    return jsonify({"query": query, "results": []}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
