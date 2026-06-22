"""
SkyGuard — Electronic Flight Bag (EFB) API Simulator
======================================================
Simulates the REST API of a modern Electronic Flight Bag application.
EFBs are tablets/systems used by pilots for charts, performance calculations,
flight planning, and datalink messaging.

This Flask app is the primary attack surface for:
  - OWASP ZAP active scanning (injection, auth bypass, info disclosure)
  - Pytest + HTTPX API contract tests
  - AI Pentest Narrator agent input

Security intentional weaknesses (for testing purposes):
  W1 — No rate limiting on /auth/token (brute-force vector)
  W2 — JWT secret is weak and hardcoded (key disclosure risk)
  W3 — /api/v1/flightplan/{id} has IDOR — no ownership check
  W4 — /api/v1/debug endpoint exposes server internals in non-prod
  W5 — Stack traces returned in error responses (information disclosure)

These are INTENTIONAL for QA demonstration. Document them, test them,
then show the fix. That is the portfolio story.

Run: flask --app efb_app run --port 5050
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from functools import wraps
from typing import Any

from flask import Flask, jsonify, request

app = Flask(__name__)

# ── Intentional weakness W2: hardcoded weak secret ───────────────────────────
JWT_SECRET = "skyguard-dev-secret-2024"   # noqa: S105 — intentional for ZAP testing
API_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# In-memory data store (no database needed for simulation)
# ---------------------------------------------------------------------------

@dataclass
class FlightPlan:
    id:           str
    owner_id:     str
    callsign:     str
    departure:    str
    destination:  str
    alt1:         str
    route:        str
    cruise_fl:    int
    fuel_kg:      float
    created_at:   str

@dataclass
class User:
    id:       str
    username: str
    role:     str          # "pilot", "dispatcher", "maintenance"
    password_hash: str

def _hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

USERS: dict[str, User] = {
    "u001": User("u001", "capt_dubois",   "pilot",       _hash_pw("Fl1ghts1m!")),
    "u002": User("u002", "fo_martin",     "pilot",       _hash_pw("C0p1lot99")),
    "u003": User("u003", "disp_lambert",  "dispatcher",  _hash_pw("D1spatch#")),
    "u004": User("u004", "maint_torres",  "maintenance", _hash_pw("M41nt3n@nce")),
}

FLIGHT_PLANS: dict[str, FlightPlan] = {
    "fp001": FlightPlan(
        id="fp001", owner_id="u001", callsign="AFR123",
        departure="LFPG", destination="EGLL",
        alt1="EBBR", route="OKRIB UM25 DVR L9 LATOK",
        cruise_fl=350, fuel_kg=12400.0,
        created_at="2024-01-15T08:00:00Z",
    ),
    "fp002": FlightPlan(
        id="fp002", owner_id="u002", callsign="AFR456",
        departure="LFPG", destination="KJFK",
        alt1="KBOS", route="DEKOD NATB RAFOX",
        cruise_fl=380, fuel_kg=48000.0,
        created_at="2024-01-15T09:30:00Z",
    ),
}

METAR_CACHE: dict[str, dict] = {
    "LFPG": {"icao": "LFPG", "raw": "LFPG 150800Z 28012KT 9999 FEW030 12/05 Q1013", "visibility_m": 9999, "wind_kt": 12},
    "EGLL": {"icao": "EGLL", "raw": "EGLL 150750Z 25015KT 8000 SCT025 10/07 Q1010", "visibility_m": 8000, "wind_kt": 15},
    "KJFK": {"icao": "KJFK", "raw": "KJFK 150800Z 32008KT 10SM CLR 05/M03 A2990",  "visibility_m": 16000, "wind_kt": 8},
}

# Simple in-memory token store {token: user_id}
ACTIVE_TOKENS: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _generate_token(user_id: str) -> str:
    """Generate a simple HMAC token (not real JWT — simplified for simulation)."""
    payload = f"{user_id}:{time.time()}"
    sig = hmac.new(JWT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    token = f"{payload}:{sig}"
    ACTIVE_TOKENS[token] = user_id
    return token


def require_auth(f):
    """Decorator: validate Bearer token and inject current_user into kwargs."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing or malformed Authorization header"}), 401
        token = auth[7:]
        user_id = ACTIVE_TOKENS.get(token)
        if not user_id:
            return jsonify({"error": "Invalid or expired token"}), 401
        user = USERS.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 401
        return f(*args, current_user=user, **kwargs)
    return decorated


def require_role(role: str):
    """Decorator: restrict endpoint to a specific role."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, current_user: User, **kwargs):
            if current_user.role != role:
                return jsonify({
                    "error": "Forbidden",
                    "required_role": role,
                    "your_role": current_user.role,
                }), 403
            return f(*args, current_user=current_user, **kwargs)
        return decorated
    return decorator


# ---------------------------------------------------------------------------
# Routes — public
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "version": API_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": platform.node(),     # W5: leaks hostname
    })


@app.route("/api/v1/version", methods=["GET"])
def version():
    return jsonify({
        "api_version":  API_VERSION,
        "python":       platform.python_version(),   # W5: info disclosure
        "server":       platform.system(),
        "build":        "skyguard-efb-sim-dev",
    })


# ── W1: No rate limiting ──────────────────────────────────────────────────────
@app.route("/api/v1/auth/token", methods=["POST"])
def auth_token():
    """
    Authenticate and return a Bearer token.
    Weakness W1: no rate limiting — susceptible to credential stuffing.
    """
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password  = body.get("password", "")

    user = next((u for u in USERS.values() if u.username == username), None)
    if not user or user.password_hash != _hash_pw(password):
        # W5: error message distinguishes 'user not found' vs 'bad password'
        # in a real system — here we intentionally unify, but the timing side-
        # channel still exists (hash comparison vs lookup).
        return jsonify({"error": "Invalid credentials"}), 401

    token = _generate_token(user.id)
    return jsonify({
        "access_token": token,
        "token_type":   "Bearer",
        "user_id":      user.id,
        "role":         user.role,
    })


@app.route("/api/v1/auth/logout", methods=["POST"])
@require_auth
def auth_logout(current_user: User):
    auth  = request.headers.get("Authorization", "")[7:]
    ACTIVE_TOKENS.pop(auth, None)
    return jsonify({"message": "Logged out"})


# ---------------------------------------------------------------------------
# Flight plan routes
# ---------------------------------------------------------------------------

@app.route("/api/v1/flightplans", methods=["GET"])
@require_auth
def list_flightplans(current_user: User):
    """Return flight plans. Pilots see only their own; dispatchers see all."""
    if current_user.role == "dispatcher":
        plans = list(FLIGHT_PLANS.values())
    else:
        plans = [p for p in FLIGHT_PLANS.values() if p.owner_id == current_user.id]
    return jsonify({"flight_plans": [asdict(p) for p in plans], "count": len(plans)})


# ── W3: IDOR — no ownership validation ───────────────────────────────────────
@app.route("/api/v1/flightplans/<plan_id>", methods=["GET"])
@require_auth
def get_flightplan(plan_id: str, current_user: User):
    """
    Retrieve a specific flight plan.
    Weakness W3: IDOR — any authenticated user can fetch any plan by ID.
    Fix would be: check plan.owner_id == current_user.id (unless dispatcher).
    """
    plan = FLIGHT_PLANS.get(plan_id)
    if not plan:
        return jsonify({"error": f"Flight plan {plan_id!r} not found"}), 404
    # W3: missing ownership check here
    return jsonify(asdict(plan))


@app.route("/api/v1/flightplans", methods=["POST"])
@require_auth
def create_flightplan(current_user: User):
    """Create a new flight plan."""
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be JSON"}), 400

    required = {"callsign", "departure", "destination", "route", "cruise_fl", "fuel_kg"}
    missing = required - body.keys()
    if missing:
        return jsonify({"error": f"Missing fields: {sorted(missing)}"}), 422

    # Bug fix (caught by injection tests): int()/float() on None or non-numeric
    # strings raised an unhandled TypeError/ValueError → 500.
    # Now returns 422 with a descriptive error — W5 surface reduced.
    try:
        cruise_fl = int(body["cruise_fl"])
        fuel_kg   = float(body["fuel_kg"])
    except (TypeError, ValueError) as exc:
        return jsonify({"error": f"Invalid numeric field: {exc}"}), 422

    # Guard against None in string fields before slicing
    try:
        callsign    = str(body["callsign"])[:10]
        departure   = str(body["departure"])[:4].upper()
        destination = str(body["destination"])[:4].upper()
        alt1        = str(body.get("alt1") or "")[:4].upper()
        route       = str(body["route"])[:500]
    except (TypeError, AttributeError) as exc:
        return jsonify({"error": f"Invalid string field: {exc}"}), 422

    plan_id = f"fp{uuid.uuid4().hex[:6]}"
    plan = FlightPlan(
        id=plan_id,
        owner_id=current_user.id,
        callsign=callsign,
        departure=departure,
        destination=destination,
        alt1=alt1,
        route=route,
        cruise_fl=cruise_fl,
        fuel_kg=fuel_kg,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    FLIGHT_PLANS[plan_id] = plan
    return jsonify(asdict(plan)), 201


@app.route("/api/v1/flightplans/<plan_id>", methods=["DELETE"])
@require_auth
def delete_flightplan(plan_id: str, current_user: User):
    plan = FLIGHT_PLANS.get(plan_id)
    if not plan:
        return jsonify({"error": "Not found"}), 404
    if plan.owner_id != current_user.id and current_user.role != "dispatcher":
        return jsonify({"error": "Forbidden"}), 403
    del FLIGHT_PLANS[plan_id]
    return jsonify({"message": f"Flight plan {plan_id} deleted"}), 200


# ---------------------------------------------------------------------------
# Weather / METAR routes
# ---------------------------------------------------------------------------

@app.route("/api/v1/weather/<icao>", methods=["GET"])
@require_auth
def get_metar(icao: str, current_user: User):
    metar = METAR_CACHE.get(icao.upper())
    if not metar:
        return jsonify({"error": f"No METAR available for {icao.upper()}"}), 404
    return jsonify(metar)


@app.route("/api/v1/weather", methods=["GET"])
@require_auth
def list_weather(current_user: User):
    return jsonify({"stations": list(METAR_CACHE.values()), "count": len(METAR_CACHE)})


# ---------------------------------------------------------------------------
# Performance calculation route
# ---------------------------------------------------------------------------

@app.route("/api/v1/performance/takeoff", methods=["POST"])
@require_auth
def takeoff_performance(current_user: User):
    """
    Simple takeoff distance calculation.
    Input validation is intentionally minimal for ZAP injection testing.
    """
    body = request.get_json(silent=True) or {}
    try:
        weight_kg = float(body.get("weight_kg", 0))
        temp_c    = float(body.get("oat_celsius", 15))
        elevation_ft = float(body.get("airport_elevation_ft", 0))
        flap_setting = str(body.get("flap_setting", "FLAP1"))
    except (ValueError, TypeError) as exc:
        # W5: raw exception message returned to client
        return jsonify({"error": str(exc)}), 400

    # Simplified calculation — not for real flight use
    base_distance_m = weight_kg * 0.085
    temp_factor     = 1 + (temp_c - 15) * 0.008
    elevation_factor = 1 + elevation_ft * 0.00003
    tod_m = base_distance_m * temp_factor * elevation_factor

    return jsonify({
        "takeoff_distance_m":  round(tod_m),
        "weight_kg":           weight_kg,
        "oat_celsius":         temp_c,
        "airport_elevation_ft": elevation_ft,
        "flap_setting":        flap_setting,
        "note":                "Simulation only — not for flight use",
    })


# ---------------------------------------------------------------------------
# Maintenance route — restricted
# ---------------------------------------------------------------------------

@app.route("/api/v1/maintenance/systems", methods=["GET"])
@require_auth
@require_role("maintenance")
def maintenance_systems(current_user: User):
    return jsonify({
        "systems": [
            {"id": "ADS-B",  "status": "nominal", "last_check": "2024-01-14"},
            {"id": "ACARS",  "status": "nominal", "last_check": "2024-01-14"},
            {"id": "FMS",    "status": "nominal", "last_check": "2024-01-13"},
            {"id": "ILS-CAT3","status": "nominal","last_check": "2024-01-12"},
        ],
        "aircraft": "F-GKXA",
        "checked_by": current_user.username,
    })


# ── W4: Debug endpoint — exposes internals ────────────────────────────────────
@app.route("/api/v1/debug", methods=["GET"])
def debug_endpoint():
    """
    Weakness W4: debug endpoint with no authentication.
    Exposes active tokens, user list, and environment info.
    Should not exist in production — ZAP and Bandit will flag this.
    """
    if os.environ.get("FLASK_ENV") == "production":
        return jsonify({"error": "Not available in production"}), 403

    return jsonify({
        "active_tokens":  list(ACTIVE_TOKENS.keys()),
        "users":          {uid: u.username for uid, u in USERS.items()},
        "flight_plans":   list(FLIGHT_PLANS.keys()),
        "jwt_secret":     JWT_SECRET,         # critical exposure
        "environment":    dict(os.environ),   # full env dump
    })


# ---------------------------------------------------------------------------
# Error handlers — W5: stack traces in responses
# ---------------------------------------------------------------------------

@app.errorhandler(Exception)
def handle_exception(e: Exception):
    """
    Weakness W5: unhandled exceptions return full Python stack trace.
    A production EFB API should return only a generic error ID.
    """
    import traceback
    return jsonify({
        "error":     "Internal server error",
        "exception": str(e),
        "traceback": traceback.format_exc(),   # W5: information disclosure
    }), 500


@app.errorhandler(404)
def handle_404(e):
    return jsonify({"error": "Endpoint not found", "path": request.path}), 404


@app.errorhandler(405)
def handle_405(e):
    return jsonify({
        "error":   "Method not allowed",
        "allowed": e.valid_methods,
    }), 405


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)
