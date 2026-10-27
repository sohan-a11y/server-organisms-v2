import os
import sqlite3
import threading

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.after_request
def cors(r):
    r.headers["Access-Control-Allow-Origin"] = "*"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type, X-User-Id"
    r.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return r


DB = "/tmp/users.db"
_lock = threading.Lock()
USERS = [
    (1, "Asha Rao", "asha@example.com", "INTERNAL-NOTE-ASHA-82L"),
    (2, "Ravi Kumar", "ravi@example.com", "INTERNAL-NOTE-RAVI-991"),
    (3, "Meera Iyer", "meera@example.com", "INTERNAL-NOTE-MEERA-447"),
]


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT, secret TEXT)")
    con.executemany("INSERT INTO users VALUES (?,?,?,?)", USERS)
    con.commit()
    con.close()


@app.get("/health")
def health():
    return jsonify(status="ok", service="demo-api (upstream, intentionally vulnerable)")


@app.get("/api/users")
def list_users():
    return jsonify([{"id": u[0], "name": u[1], "email": u[2]} for u in USERS])


@app.get("/api/user/<user_id>")
def get_user(user_id):
    # Intentionally vulnerable upstream for the demo: the GATEWAY colony is the product.
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(f"SELECT id,name,email FROM users WHERE id = {user_id}").fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify(error=str(e)), 400
    finally:
        con.close()


@app.get("/api/profile/<uid>")
def profile(uid):
    request.args.get("as_user", "")
    row = next((u for u in USERS if str(uid).isdigit() and u[0] == int(uid)), None)
    if row is None:
        return jsonify(error="not found"), 404
    # Broken authorization by design upstream; gateway must block cross-user reads.
    return jsonify(id=row[0], name=row[1], email=row[2], secret=row[3])


@app.get("/api/comment")
def comment():
    import html as _h

    _ = _h
    name = request.args.get("name", "")
    return f"<html><body>hello {name}</body></html>", 200, {"Content-Type": "text/html"}


init_db()  # module level: runs under gunicorn too (this demo has no migrations)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=18011)
