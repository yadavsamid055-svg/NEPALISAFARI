from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, g, jsonify, make_response, request, send_from_directory

ROOT = Path(__file__).resolve().parent
INSTANCE = ROOT / ".instance"
INSTANCE.mkdir(exist_ok=True)
DATABASE = Path(os.environ.get("NEPALISAFARI_DATABASE", INSTANCE / "nepalisafari.sqlite3"))
MAX_IMAGE_BYTES = 5 * 1024 * 1024
IMAGE_MIME_TYPES = {"image/jpeg", "image/png", "image/webp"}


def secret_file(name: str, make_value: Any) -> bytes:
    path = INSTANCE / name
    if path.exists():
        return path.read_bytes()
    value = make_value()
    path.write_bytes(value)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return value


app = Flask(__name__, static_folder=None)
app.config.update(
    SECRET_KEY=secret_file("session.secret", lambda: secrets.token_bytes(48)),
    MAX_CONTENT_LENGTH=15 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("NEPALISAFARI_HTTPS") == "1",
)
fernet = Fernet(secret_file("documents.key", Fernet.generate_key))


def connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def initialize_db() -> None:
    with connect_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                phone TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL CHECK(role IN ('passenger','owner','admin')),
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                vehicle TEXT,
                vehicle_plate TEXT,
                license_number TEXT,
                profile_photo BLOB,
                license_photo BLOB,
                active INTEGER NOT NULL DEFAULT 1,
                id_verified INTEGER NOT NULL DEFAULT 0,
                referral_code TEXT NOT NULL UNIQUE,
                referral_points INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                csrf_token TEXT NOT NULL,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS records (
                collection TEXT NOT NULL,
                id TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(collection, id)
            );
            CREATE INDEX IF NOT EXISTS idx_records_owner ON records(collection, owner_id);
            """
        )
    db.close()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_error(message: str, status: int = 400):
    return jsonify(error=message), status


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return salt, digest


def decode_image(value: Any) -> bytes | None:
    if not value:
        return None
    if not isinstance(value, str) or len(value) > (MAX_IMAGE_BYTES * 4 // 3) + 256:
        raise ValueError("Image is invalid or larger than 5 MB.")
    match = re.fullmatch(r"data:(image/(?:jpeg|png|webp));base64,([A-Za-z0-9+/]+={0,2})", value)
    if not match or match.group(1) not in IMAGE_MIME_TYPES:
        raise ValueError("Upload a JPG, PNG, or WebP image.")
    try:
        image = base64.b64decode(match.group(2), validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("The selected image could not be read.") from error
    if not image or len(image) > MAX_IMAGE_BYTES:
        raise ValueError("Image must be smaller than 5 MB.")
    mime = match.group(1)
    valid_signature = (
        mime == "image/png" and image.startswith(b"\x89PNG\r\n\x1a\n")
        or mime == "image/jpeg" and image.startswith(b"\xff\xd8\xff")
        or mime == "image/webp" and len(image) >= 12 and image[:4] == b"RIFF" and image[8:12] == b"WEBP"
    )
    if not valid_signature:
        raise ValueError("The selected file contents do not match a supported image.")
    return fernet.encrypt(image)


def image_data(value: bytes | None) -> str:
    if not value:
        return ""
    try:
        image = fernet.decrypt(value)
    except InvalidToken as error:
        raise RuntimeError("Stored image could not be decrypted; check the document encryption key.") from error
    if image.startswith(b"\x89PNG\r\n\x1a\n"):
        mime = "image/png"
    elif image.startswith(b"\xff\xd8\xff"):
        mime = "image/jpeg"
    elif len(image) >= 12 and image[:4] == b"RIFF" and image[8:12] == b"WEBP":
        mime = "image/webp"
    else:
        raise RuntimeError("Stored image is not a supported image format.")
    return f"data:{mime};base64,{base64.b64encode(image).decode('ascii')}"


def user_record(row: sqlite3.Row, include_private: bool = False, include_contact: bool = False) -> dict[str, Any]:
    user = {
        "id": row["id"],
        "name": row["name"],
        "role": row["role"],
        "active": bool(row["active"]),
        "vehicle": row["vehicle"] or "",
        "profilePhotoAvailable": bool(row["profile_photo"]),
        "licensePhotoAvailable": bool(row["license_photo"]),
        "idVerified": bool(row["id_verified"]),
        "referralCode": row["referral_code"],
        "referralPoints": row["referral_points"],
        "walletBalance": 0,
    }
    if include_contact:
        user.update(email=row["email"], phone=row["phone"])
    if include_private:
        user.update(
            vehiclePlate=row["vehicle_plate"] or "",
            licenseNumber=row["license_number"] or "",
        )
    return user


def get_session() -> tuple[sqlite3.Row, sqlite3.Row] | None:
    if getattr(g, "db", None) is not None:
        if getattr(g, "user", None) is not None:
            return g.user, g.user
        return None
    raw_token = request.cookies.get("ns_session", "")
    db = connect_db()
    g.db = db
    if not raw_token:
        return None
    token_hash = hashlib.sha256(raw_token.encode("ascii", "ignore")).hexdigest()
    row = db.execute(
        """SELECT s.token_hash, s.csrf_token, s.expires_at, u.*
           FROM sessions s JOIN users u ON u.id=s.user_id
           WHERE s.token_hash=?""",
        (token_hash,),
    ).fetchone()
    if not row:
        return None
    if row["expires_at"] <= now_iso() or not row["active"]:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
        db.commit()
        return None
    g.db = db
    g.user = row
    g._csrf_token = row["csrf_token"]
    return row, row


def require_auth(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        if not get_session():
            return json_error("Please sign in to continue.", 401)
        return handler(*args, **kwargs)
    return wrapped


def require_admin() -> bool:
    return g.user["role"] == "admin"


@app.before_request
def open_connection_and_check_origin():
    if request.path.startswith("/api/") and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("Origin")
        if origin:
            expected = f"{request.scheme}://{request.host}"
            if origin.rstrip("/") != expected.rstrip("/"):
                return json_error("Cross-origin request rejected.", 403)
    if request.path.startswith("/api/") and request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.path not in {"/api/register", "/api/login"}:
        get_session()
        if not getattr(g, "user", None):
            return json_error("Please sign in to continue.", 401)
        if not hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), g._csrf_token):
            return json_error("Request verification failed. Reload and try again.", 403)
    elif request.path.startswith("/api/"):
        get_session()


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/") else "no-cache"
    response.headers["Content-Security-Policy"] = "default-src 'self' https://unpkg.com https://*.tile.openstreetmap.org; img-src 'self' data: https://*.tile.openstreetmap.org; style-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; script-src 'self' 'unsafe-inline' https://unpkg.com; connect-src 'self' https://*.tile.openstreetmap.org; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    db = getattr(g, "db", None)
    if db is not None:
        db.close()
    return response


def create_session(db: sqlite3.Connection, user_id: str):
    raw = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw.encode("ascii")).hexdigest()
    csrf = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc).replace(microsecond=0)
    from datetime import timedelta
    expires += timedelta(days=14)
    db.execute(
        "INSERT INTO sessions(token_hash,csrf_token,user_id,expires_at) VALUES(?,?,?,?)",
        (token_hash, csrf, user_id, expires.isoformat()),
    )
    db.commit()
    response = make_response(jsonify(ok=True, csrfToken=csrf))
    response.set_cookie("ns_session", raw, httponly=True, secure=app.config["SESSION_COOKIE_SECURE"], samesite="Strict", max_age=14 * 24 * 60 * 60, path="/")
    return response


def clean_text(value: Any, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def generated_code(db: sqlite3.Connection) -> str:
    while True:
        code = "NS" + secrets.token_hex(4).upper()
        if not db.execute("SELECT 1 FROM users WHERE referral_code=?", (code,)).fetchone():
            return code


@app.get("/")
def index():
    return send_from_directory(ROOT, "index.html")


@app.get("/api/session")
def session():
    if not get_session():
        return jsonify(authenticated=False)
    return jsonify(authenticated=True, csrfToken=g._csrf_token, user=user_record(g.user, include_private=True))


@app.get("/api/users/<user_id>/image/<kind>")
def user_image(user_id: str, kind: str):
    if not get_session():
        return json_error("Please sign in to continue.", 401)
    if kind not in {"profile", "license"}:
        return json_error("Image not found.", 404)
    if user_id != g.user["id"] and not require_admin():
        return json_error("You do not have permission to view this image.", 403)
    column = "profile_photo" if kind == "profile" else "license_photo"
    row = g.db.execute(f"SELECT {column} FROM users WHERE id=?", (user_id,)).fetchone()
    if not row or not row[column]:
        return json_error("Image not found.", 404)
    try:
        encrypted = row[column]
        image = fernet.decrypt(encrypted)
    except InvalidToken as error:
        raise RuntimeError("Stored image could not be decrypted; check the document encryption key.") from error
    mime = "image/png" if image.startswith(b"\x89PNG\r\n\x1a\n") else "image/jpeg" if image.startswith(b"\xff\xd8\xff") else "image/webp"
    response = app.response_class(image, mimetype=mime)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    name = clean_text(data.get("name"), 120)
    email = clean_text(data.get("email"), 254).lower()
    phone = clean_text(data.get("phone"), 30)
    normalized_phone = re.sub(r"\D", "", phone)
    role = data.get("role")
    password = data.get("password")
    if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return json_error("Enter your name and a valid email address.")
    if not 7 <= len(normalized_phone) <= 15:
        return json_error("Enter a valid phone number.")
    if role not in {"passenger", "owner"}:
        return json_error("Choose passenger or vehicle owner.")
    if not isinstance(password, str) or len(password) < 12 or len(password) > 256:
        return json_error("Use a password between 12 and 256 characters.")
    vehicle = clean_text(data.get("vehicle"), 120)
    plate = clean_text(data.get("vehiclePlate"), 40)
    license_number = clean_text(data.get("licenseNumber"), 80)
    if role == "owner" and not (vehicle and plate and license_number):
        return json_error("Vehicle owners must provide vehicle, plate, and licence details.")
    invite_code = clean_text(data.get("inviteCode"), 32).upper()
    try:
        profile_image = decode_image(data.get("profilePhotoData"))
        license_image = decode_image(data.get("licensePhotoData")) if role == "owner" else None
    except ValueError as error:
        return json_error(str(error))
    if not profile_image or role == "owner" and not license_image:
        return json_error("Upload the required profile photo and, for owners, licence photo.")
    db = connect_db()
    inviter = None
    if invite_code:
        inviter = db.execute("SELECT id FROM users WHERE referral_code=?", (invite_code,)).fetchone()
        if not inviter or role != "passenger":
            db.close()
            return json_error("This invite code is invalid or only applies to passenger accounts.")
    salt, password_hash = hash_password(password)
    user_id = "NS-" + secrets.token_hex(5).upper()
    try:
        db.execute(
            """INSERT INTO users(id,name,email,phone,role,password_salt,password_hash,
               vehicle,vehicle_plate,license_number,profile_photo,license_photo,referral_code,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (user_id, name, email, normalized_phone, role, salt, password_hash, vehicle or None, plate or None,
             license_number or None, profile_image, license_image, generated_code(db), now_iso()),
        )
        if inviter:
            referral = {
                "id": "NS-REF-" + secrets.token_hex(4).upper(),
                "inviterId": inviter["id"],
                "inviteeId": user_id,
                "inviteCode": invite_code,
                "status": "pending",
                "rewardPoints": 0,
                "createdAt": now_iso(),
            }
            save_time = now_iso()
            db.execute(
                "INSERT INTO records(collection,id,owner_id,payload,created_at,updated_at) VALUES('referrals',?,?,?,?,?)",
                (referral["id"], inviter["id"], json.dumps(referral), save_time, save_time),
            )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return json_error("That email address or phone number already has an account.", 409)
    response = create_session(db, user_id)
    db.close()
    return response, 201


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    identity = clean_text(data.get("identity"), 254).lower()
    password = data.get("password")
    if not identity or not isinstance(password, str):
        return json_error("Enter your email or phone number and password.")
    db = connect_db()
    user = db.execute(
        "SELECT * FROM users WHERE email=? COLLATE NOCASE OR phone=?",
        (identity, re.sub(r"\D", "", identity)),
    ).fetchone()
    if not user or not hmac.compare_digest(hash_password(password, user["password_salt"])[1], user["password_hash"]):
        db.close()
        return json_error("Email/phone or password is incorrect.", 401)
    if not user["active"]:
        db.close()
        return json_error("This account has been suspended. Contact the site administrator.", 403)
    response = create_session(db, user["id"])
    db.close()
    return response


@app.post("/api/logout")
@require_auth
def logout():
    raw_token = request.cookies.get("ns_session", "")
    token_hash = hashlib.sha256(raw_token.encode("ascii", "ignore")).hexdigest()
    g.db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
    g.db.commit()
    response = make_response(jsonify(ok=True))
    response.delete_cookie("ns_session", path="/", httponly=True, samesite="Strict")
    return response


@app.get("/api/payments/config")
def payment_config():
    return jsonify(available=False, message="Online payment processing is not implemented yet.")


def record_payload(collection: str, item_id: str) -> tuple[sqlite3.Row | None, dict[str, Any] | None]:
    row = g.db.execute(
        "SELECT * FROM records WHERE collection=? AND id=?",
        (collection, item_id),
    ).fetchone()
    return (row, json.loads(row["payload"]) if row else None)


def save_record(collection: str, item: dict[str, Any], owner_id: str, existing: bool) -> None:
    timestamp = now_iso()
    encoded = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
    if existing:
        g.db.execute(
            "UPDATE records SET payload=?,updated_at=? WHERE collection=? AND id=?",
            (encoded, timestamp, collection, item["id"]),
        )
    else:
        g.db.execute(
            "INSERT INTO records(collection,id,owner_id,payload,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (collection, item["id"], owner_id, encoded, timestamp, timestamp),
        )


def visible_records(collection: str) -> list[dict[str, Any]]:
    rows = g.db.execute("SELECT id,owner_id,payload FROM records WHERE collection=?", (collection,)).fetchall()
    result = []
    for row in rows:
        item = json.loads(row["payload"])
        if collection in {"bookings", "complaints", "referrals"} and not require_admin():
            if collection == "bookings":
                ride = record_payload("rides", item.get("rideId", ""))[1]
                if item.get("passenger") != g.user["id"] and (not ride or ride.get("owner") != g.user["id"]):
                    continue
            elif collection == "complaints" and item.get("passenger") != g.user["id"]:
                continue
            elif collection == "referrals" and item.get("inviterId") != g.user["id"]:
                continue
        if collection == "messages" and not require_admin():
            booking = record_payload("bookings", item.get("bookingId", ""))[1]
            ride = record_payload("rides", booking.get("rideId", ""))[1] if booking else None
            if not booking or (booking.get("passenger") != g.user["id"] and (not ride or ride.get("owner") != g.user["id"])):
                continue
        result.append(item)
    return result


def process_users(incoming: Any) -> None:
    if not isinstance(incoming, list):
        raise ValueError("Invalid account data.")
    if not require_admin():
        return
    for item in incoming:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            continue
        db_user = g.db.execute("SELECT * FROM users WHERE id=?", (item["id"],)).fetchone()
        if not db_user:
            continue
        active = int(bool(item.get("active", db_user["active"])))
        verified = int(bool(item.get("idVerified", db_user["id_verified"])))
        if verified:
            full = bool(db_user["name"].strip() and db_user["email"].strip() and db_user["phone"].strip()
                        and db_user["profile_photo"] and (db_user["role"] != "owner" or
                        db_user["vehicle"] and db_user["vehicle_plate"] and db_user["license_number"] and db_user["license_photo"]))
            if not full:
                raise ValueError("This account is missing required identity details.")
        g.db.execute("UPDATE users SET active=?,id_verified=? WHERE id=?", (active, verified, item["id"]))


def process_records(collection: str, incoming: Any) -> None:
    if not isinstance(incoming, list):
        raise ValueError("Invalid account data.")
    actor = g.user["id"]
    role = g.user["role"]
    if collection == "referrals":
        return
    for submitted in incoming:
        if not isinstance(submitted, dict):
            continue
        item_id = submitted.get("id")
        if not isinstance(item_id, str) or len(item_id) > 100:
            raise ValueError(f"Invalid {collection} record.")
        row, previous = record_payload(collection, item_id)
        admin = require_admin()
        if previous == submitted:
            continue
        if collection == "rides":
            if row and not admin and row["owner_id"] != actor:
                raise PermissionError("You can only change your own ride listings.")
            if role != "owner" and not admin:
                raise PermissionError("Only vehicle owners can manage ride listings.")
            if not row and not admin and not g.user["id_verified"]:
                raise PermissionError("Your complete owner profile must be reviewed before you can post a ride.")
            allowed_status = {"active", "paused"} if not admin else {"active", "paused", "suspended"}
            status = submitted.get("status", "active")
            if status not in allowed_status:
                raise ValueError("Invalid ride status.")
            ride = dict(submitted)
            ride["owner"] = row["owner_id"] if row else actor
            ride["status"] = status
            if row:
                if not admin:
                    ride["seats"] = int(previous.get("seats", 0)) + int(submitted.get("seats", 0)) - int(previous.get("seats", 0))
                save_record(collection, ride, row["owner_id"], True)
            else:
                seats = int(ride.get("seats", 0))
                fare = float(ride.get("fare", 0))
                if seats < 1 or seats > 20 or fare <= 0 or fare > 1000000:
                    raise ValueError("Enter a valid seat count and fare.")
                save_record(collection, ride, actor, False)
            continue
        if collection == "bookings":
            booking = dict(submitted)
            if not row:
                if role != "passenger" or submitted.get("passenger") != actor or submitted.get("status") != "awaiting_owner":
                    raise PermissionError("Only passengers can request an available seat.")
                if submitted.get("termsAccepted") is not True:
                    raise ValueError("Accept the booking terms before requesting this seat.")
                ride_row, ride = record_payload("rides", submitted.get("rideId", ""))
                if not ride_row or not ride or ride.get("status") != "active" or int(ride.get("seats", 0)) < 1 or ride_row["owner_id"] == actor:
                    raise ValueError("This ride is no longer available.")
                duplicate = g.db.execute(
                    "SELECT 1 FROM records WHERE collection='bookings' AND owner_id=? AND json_extract(payload,'$.rideId')=? AND json_extract(payload,'$.status') NOT IN ('cancelled','declined')",
                    (actor, ride["id"]),
                ).fetchone()
                if duplicate:
                    raise ValueError("You already have an active request for this ride.")
                ride["seats"] = int(ride["seats"]) - 1
                save_record("rides", ride, ride_row["owner_id"], True)
                booking["passenger"] = actor
                booking["status"] = "awaiting_owner"
                booking["amount"] = ride["fare"]
                booking["payout"] = ride["fare"]
                booking["paymentMethod"] = submitted.get("paymentMethod") if submitted.get("paymentMethod") in {"esewa", "khalti"} else ""
                save_record(collection, booking, actor, False)
                continue
            ride = record_payload("rides", previous.get("rideId", ""))[1]
            is_owner = bool(ride and ride.get("owner") == actor)
            is_passenger = previous.get("passenger") == actor
            new_status = submitted.get("status", previous.get("status"))
            if admin:
                raise PermissionError("Administrators cannot alter bookings.")
            if is_owner and previous.get("status") == "awaiting_owner" and new_status in {"accepted", "declined"}:
                booking = previous | {"status": new_status}
                if new_status == "declined" and ride:
                    ride_row, ride = record_payload("rides", previous["rideId"])
                    ride["seats"] = int(ride.get("seats", 0)) + 1
                    save_record("rides", ride, ride_row["owner_id"], True)
            elif is_passenger and new_status == "cancelled" and previous.get("status") in {"awaiting_owner", "accepted", "awaiting_boarding"}:
                booking = previous | {"status": "cancelled"}
                if ride:
                    ride_row, ride = record_payload("rides", previous["rideId"])
                    ride["seats"] = int(ride.get("seats", 0)) + 1
                    save_record("rides", ride, ride_row["owner_id"], True)
            elif previous.get("status") in {"accepted", "awaiting_boarding"} and new_status in {"accepted", "awaiting_boarding", "completed"} and (is_passenger or is_owner):
                booking = previous.copy()
                if is_passenger:
                    booking["passengerCompleted"] = True
                if is_owner:
                    booking["ownerCompleted"] = True
                if booking.get("passengerCompleted") and booking.get("ownerCompleted"):
                    booking["status"] = "completed"
                    self_referral = g.db.execute(
                        "SELECT id,payload FROM records WHERE collection='referrals' AND json_extract(payload,'$.inviteeId')=? AND json_extract(payload,'$.status')='pending'",
                        (booking.get("passenger"),),
                    ).fetchone()
                    previous_trip = g.db.execute(
                        "SELECT 1 FROM records WHERE collection='bookings' AND owner_id=? AND json_extract(payload,'$.status')='completed' AND id<>? LIMIT 1",
                        (booking.get("passenger"), booking["id"]),
                    ).fetchone()
                    if self_referral and not previous_trip:
                        referral_data = json.loads(self_referral["payload"])
                        referral_data.update(status="rewarded", rewardPoints=10, rewardBookingId=booking["id"], rewardedAt=now_iso())
                        save_record("referrals", referral_data, booking["passenger"], True)
                        g.db.execute("UPDATE users SET referral_points=referral_points+10 WHERE id=?", (referral_data["inviterId"],))
                else:
                    booking["status"] = "awaiting_boarding"
            else:
                if new_status == "paid_to_owner":
                    raise ValueError("Payment is not configured. Configure an eSewa or Khalti merchant account before taking payment.")
                raise PermissionError("That booking change is not permitted.")
            save_record(collection, booking, row["owner_id"], True)
            continue
        if collection == "complaints":
            if not row:
                if role != "passenger" or submitted.get("passenger") != actor or not submitted.get("details", "").strip():
                    raise PermissionError("Only a passenger can report an issue on their own booking.")
                booking_row, booking = record_payload("bookings", submitted.get("bookingId", ""))
                if not booking_row or not booking or booking.get("passenger") != actor or booking.get("rideId") != submitted.get("rideId"):
                    raise PermissionError("The selected booking is not yours.")
                item = dict(submitted)
                item["passenger"] = actor
                item["status"] = "open"
                save_record(collection, item, actor, False)
            elif admin:
                status = submitted.get("status")
                if status not in {"open", "reviewed", "resolved"}:
                    raise ValueError("Invalid complaint status.")
                save_record(collection, previous | {"status": status}, row["owner_id"], True)
            else:
                raise PermissionError("Only administrators can update submitted complaints.")
            continue
        if collection == "ratings":
            if row:
                continue
            booking_row, booking = record_payload("bookings", submitted.get("bookingId", ""))
            if role != "passenger" or submitted.get("passenger") != actor or not booking_row or booking.get("passenger") != actor or booking.get("status") != "completed":
                raise PermissionError("Only passengers with a completed trip can submit a rating.")
            stars = int(submitted.get("stars", 0))
            if stars < 1 or stars > 5:
                raise ValueError("Choose a rating from 1 to 5 stars.")
            if g.db.execute("SELECT 1 FROM records WHERE collection='ratings' AND json_extract(payload,'$.bookingId')=?", (booking["id"],)).fetchone():
                raise ValueError("This trip has already been rated.")
            save_record(collection, dict(submitted), actor, False)
            continue
        if collection == "messages":
            if row:
                continue
            booking_row, booking = record_payload("bookings", submitted.get("bookingId", ""))
            ride_row, ride = record_payload("rides", booking.get("rideId", "")) if booking else (None, None)
            participant = bool(booking and ride and (booking.get("passenger") == actor or ride.get("owner") == actor))
            if role == "admin" or not participant or submitted.get("sender") != actor or booking.get("status") not in {"accepted", "awaiting_boarding", "paid_to_owner"}:
                raise PermissionError("Chat is available only to trip participants after the owner accepts.")
            text = clean_text(submitted.get("text"), 1000)
            if not text:
                raise ValueError("Enter a message before sending.")
            save_record(collection, dict(submitted) | {"text": text, "sender": actor}, actor, False)


@app.get("/api/data")
def get_data():
    users = g.db.execute("SELECT * FROM users ORDER BY created_at").fetchall()
    public_users = []
    for user in users:
        include_private = bool(getattr(g, "user", None) and (require_admin() or user["id"] == g.user["id"]))
        public_users.append(user_record(user, include_private=include_private, include_contact=include_private))
    if not getattr(g, "user", None):
        return jsonify(data={
            "users": public_users,
            "rides": visible_records("rides"),
            "bookings": [], "complaints": [], "ratings": visible_records("ratings"),
            "chatMessages": [], "referrals": [],
        })
    data = {
        "users": public_users,
        "rides": visible_records("rides"),
        "bookings": visible_records("bookings"),
        "complaints": visible_records("complaints"),
        "ratings": visible_records("ratings"),
        "chatMessages": visible_records("messages"),
        "referrals": visible_records("referrals"),
    }
    csrf = g._csrf_token
    return jsonify(data=data, csrfToken=csrf)


@app.put("/api/data")
@require_auth
def put_data():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return json_error("Invalid account update.")
    try:
        g.db.execute("BEGIN IMMEDIATE")
        with g.db:
            process_users(data.get("users", []))
            for payload_key, collection in (
                ("bookings", "bookings"),
                ("rides", "rides"),
                ("complaints", "complaints"),
                ("ratings", "ratings"),
                ("chatMessages", "messages"),
                ("referrals", "referrals"),
            ):
                if payload_key in data:
                    process_records(collection, data[payload_key])
    except PermissionError as error:
        return json_error(str(error), 403)
    except (ValueError, TypeError, OverflowError) as error:
        return json_error(str(error))
    return jsonify(ok=True)


@app.get("/api/health")
def health():
    return jsonify(status="ok")


initialize_db()


def create_admin() -> None:
    import getpass

    name = input("Administrator name: ").strip()
    email = input("Administrator email: ").strip().lower()
    phone = input("Administrator phone: ").strip()
    password = getpass.getpass("Administrator password (12+ characters): ")
    if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise SystemExit("A name and valid email are required.")
    if len(re.sub(r"\D", "", phone)) < 7:
        raise SystemExit("A valid phone number is required.")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")
    salt, password_hash = hash_password(password)
    db = connect_db()
    try:
        db.execute(
            """INSERT INTO users(id,name,email,phone,role,password_salt,password_hash,referral_code,created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            ("NS-ADMIN-" + secrets.token_hex(3).upper(), name, email, phone, "admin", salt,
             password_hash, generated_code(db), now_iso()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise SystemExit("That email address or phone number already has an account.")
    finally:
        db.close()
    print("Administrator account created.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "create-admin":
        create_admin()
    else:
        app.run(host=os.environ.get("NEPALISAFARI_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")), debug=False)
