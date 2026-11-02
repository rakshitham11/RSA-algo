from flask import Flask, jsonify, render_template, request
import rsa_algorithm as rsa

app = Flask(__name__)


def run(fn):
    try:
        return jsonify({"ok": True, **fn(request.get_json(silent=True) or {})})
    except rsa.RSAError as err:
        return jsonify({"ok": False, "error": str(err)}), 400


@app.route("/")
def index():
    return render_template("index.html", ascii_table=[(c, rsa.num_to_char(c)) for c in range(rsa.MIN_CHAR, rsa.MAX_CHAR + 1)])


@app.route("/api/keys", methods=["POST"])
def keys():
    def go(d):
        if d.get("random"):
            while True:
                p, q = rsa.random_prime(), rsa.random_prime()
                if p != q:
                    break
        else:
            p, q = d.get("p"), d.get("q")
        return {"keys": rsa.generate_keys(p, q, None if d.get("random") else d.get("e"))}
    return run(go)


@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    return run(lambda d: rsa.encrypt_message(d.get("p"), d.get("q"), d.get("plaintext"), d.get("e")))


@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    return run(lambda d: rsa.decrypt_message(d.get("p"), d.get("q"), d.get("cipher"), d.get("e")))


if __name__ == "__main__":
    app.run(debug=True)
