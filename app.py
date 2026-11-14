
import os
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "development-secret-change-me")

DB_PATH = os.path.join(app.root_path, "wallet.db")

TRACKER_TOKEN = os.environ.get(
    "TRACKER_TOKEN", "dev-tracker-token"
)

locations = {
    "wallet-001": {
        "lat": 3.1390,
        "lon": 101.6869,
        "updated": "Demo location — not live GPS"
    }
}


# DATABASE
def get_db():
    return sqlite3.connect(DB_PATH)


def initialize_database():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS owner (
                id INTEGER PRIMARY KEY,
                pin_hash TEXT NOT NULL
            )
        """)


def pin_exists():
    with get_db() as db:
        result = db.execute(
            "SELECT id FROM owner LIMIT 1"
        ).fetchone()
        return result is not None


initialize_database()


# AUTHENTICATION
def owner_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("owner_logged_in"):
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


# FIRST-TIME PIN SETUP
@app.route("/setup", methods=["GET", "POST"])
def setup():
    if pin_exists():
        return redirect(url_for("login"))

    error = None

    if request.method == "POST":
        pin = request.form.get("pin", "")
        confirm_pin = request.form.get("confirm_pin", "")

        if not pin.isdigit() or not 4 <= len(pin) <= 12:
            error = "PIN must contain 4 to 12 digits."

        elif pin != confirm_pin:
            error = "PINs do not match."

        else:
            hashed_pin = generate_password_hash(pin)

            with get_db() as db:
                db.execute(
                    "INSERT INTO owner (pin_hash) VALUES (?)",
                    (hashed_pin,)
                )

            return redirect(url_for("login"))

    return render_template("setup.html", error=error)


# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if not pin_exists():
        return redirect(url_for("setup"))

    error = None

    if request.method == "POST":
        pin = request.form.get("pin", "")

        with get_db() as db:
            result = db.execute(
                "SELECT pin_hash FROM owner LIMIT 1"
            ).fetchone()

        if result and check_password_hash(result[0], pin):
            session["owner_logged_in"] = True
            return redirect(url_for(
                "wallet_page", wallet_id="wallet-001"
            ))

        error = "Incorrect PIN. Try again."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# WALLET PAGE
@app.route("/wallet/<wallet_id>")
@owner_required
def wallet_page(wallet_id):
    if wallet_id not in locations:
        return "Wallet not found", 404

    return render_template(
        "wallet.html", wallet_id=wallet_id
    )


# GPS LOCATION API
@app.route("/api/location/<wallet_id>", methods=["GET", "POST"])
def location_api(wallet_id):
    if wallet_id not in locations:
        return jsonify({"error": "Wallet not found"}), 404

    if request.method == "GET":
        if not session.get("owner_logged_in"):
            return jsonify({"error": "Login required"}), 401

        return jsonify(locations[wallet_id])

    if request.headers.get("X-Tracker-Token") != TRACKER_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}

    try:
        lat = float(data["lat"])
        lon = float(data["lon"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "Invalid coordinates"}), 400

    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return jsonify({"error": "Coordinates out of range"}), 400

    locations[wallet_id] = {
        "lat": lat,
        "lon": lon,
        "updated": datetime.now(timezone.utc).isoformat()
    }

    return jsonify({"status": "updated"})


if __name__ == "__main__":
    app.run(debug=True)
