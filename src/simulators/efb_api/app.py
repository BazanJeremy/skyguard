"""
Electronic Flight Bag (EFB) API Simulator
==========================================
Simulates the REST API surface of a modern EFB application.

EFBs are tablet/laptop-based systems that replace paper manuals in the cockpit.
They connect to airline ground networks (via Wi-Fi at gate, VHF ACARS in-flight)
and expose internal APIs consumed by navigation, weather, and fuel apps.

Security relevance (per EASA AMC 20-25, Section 6):
  - EFBs are classified as aircraft electronic hardware when Type B
  - Network connectivity (VPN, ACARS link) makes them an attack vector
  - Vulnerabilities: unauth endpoints, injection, IDOR, missing rate limiting

This simulator deliberately includes testable weaknesses:
  - /api/v1/flight-plan: no authentication required (missing auth)
  - /api/v1/crew-message: no input length limit enforced
  - /api/v1/fuel: accepts negative uplift values (business logic flaw)
  - /api/v1/charts: path traversal not fully sanitised

ZAP and Pytest+HTTPX tests target these endpoints.
"""

from __future__ import annotations

import os
import re
import time
from typing import Any

from flask import Flask, jsonify, request, Response

app = Flask(__name__)
app.config["TESTING"] = False

# ─────────────────────────────────────────────────────────────────────────────
# In-memory state (no persistence — resets on restart)
# ─────────────────────────────────────────────────────────────────────────────

_FLIGHT_PLANS: dict[str, dict] = {
    "AF447": {
        "flight_id": "AF447",
        "origin": "EGLL",
        "destination": "LFPG",
        "std": "2024-01-28T08:30:00Z",
        "aircraft": "FHBXA",
        "fuel_planned_kg": 18500,
        "route": "WOBUN2F DCT MONAK UM605 REPSI",
        "alternates": ["LFOB", "LFBD"],
    },
    "BA123": {
        "flight_id": "BA123",
        "origin": "LFPG",
        "destination": "LEMD",
        "std": "2024-01-28T11:00:00Z",
        "aircraft": "GBXYZ",
        "fuel_planned_kg": 12000,
        "route": "RANUX1E DCT TOLTU UZ4 RESMI",
        "alternates": ["LEBB"],
    },
}

_CREW_MESSAGES: list[dict] = []
_FUEL_LOG: list[dict] = []
_AUDIT_LOG: list[dict] = []


def _audit(event: str, data: dict) -> None:
    _AUDIT_LOG.append(
        {
            "timestamp": time.time(),
            "event": event,
            "remote_addr": request.remote_addr,
            "data": data,
        }
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _json_response(data: Any, status: int = 200) -> Response:
    return jsonify(data), status


def _error(message: str, status: int = 400) -> Response:
    return _json_response({"error": message}, status)


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────


@app.route("/health")
def health() -> Response:
    """Health check — used by CI to wait for server readiness."""
    return _json_response({"status": "ok", "service": "efb-simulator"})


# ── VULNERABILITY 1: No authentication on flight plan endpoint ───────────────


@app.route("/api/v1/flight-plan/<flight_id>", methods=["GET"])
def get_flight_plan(flight_id: str) -> Response:
    """
    Retrieve flight plan data.

    VULNERABILITY: No authentication token required.
    Any client on the network can read all flight plans.
    ZAP will flag this as 'Missing Authentication'.
    """
    _audit("flight_plan_read", {"flight_id": flight_id})

    if flight_id not in _FLIGHT_PLANS:
        return _error(f"Flight {flight_id!r} not found.", 404)

    return _json_response(_FLIGHT_PLANS[flight_id])


@app.route("/api/v1/flight-plans", methods=["GET"])
def list_flight_plans() -> Response:
    """
    List all flight plans.

    VULNERABILITY: IDOR — returns all plans without ownership check.
    Attacker can enumerate all flights loaded on this EFB.
    """
    return _json_response(list(_FLIGHT_PLANS.values()))


# ── VULNERABILITY 2: No input length limit on crew message ──────────────────


@app.route("/api/v1/crew-message", methods=["POST"])
def post_crew_message() -> Response:
    """
    Submit a crew text message for ACARS transmission.

    VULNERABILITY: Body length not validated.
    Sending a >220-char message (ARINC 618 limit) causes downstream
    ACARS encoder to silently truncate, losing part of the message.

    Also: no XSS sanitization on 'message' field.
    """
    data = request.get_json(silent=True) or {}
    flight_id = data.get("flight_id", "")
    message = data.get("message", "")
    priority = data.get("priority", "ROUTINE")

    if not flight_id or not message:
        return _error("'flight_id' and 'message' are required.")

    # INTENTIONAL: no length check here
    entry = {
        "id": len(_CREW_MESSAGES) + 1,
        "flight_id": flight_id,
        "message": message,  # raw — unsanitised
        "priority": priority,
        "timestamp": time.time(),
        "status": "QUEUED",
    }
    _CREW_MESSAGES.append(entry)
    _audit("crew_message_queued", {"flight_id": flight_id, "length": len(message)})

    return _json_response({"id": entry["id"], "status": "QUEUED"}, 201)


@app.route("/api/v1/crew-messages", methods=["GET"])
def list_crew_messages() -> Response:
    """
    List all crew messages.

    VULNERABILITY: No authentication; any client can read crew comms.
    """
    return _json_response(_CREW_MESSAGES)


# ── VULNERABILITY 3: Business logic flaw in fuel endpoint ───────────────────


@app.route("/api/v1/fuel/uplift", methods=["POST"])
def request_fuel_uplift() -> Response:
    """
    Submit a fuel uplift request to the ground handler.

    VULNERABILITY: Accepts negative uplift_kg (no positive-value assertion).
    A negative fuel order could confuse the fuel management system into
    reporting a false total, or be used to deny fuel to the aircraft.
    """
    data = request.get_json(silent=True) or {}
    flight_id = data.get("flight_id", "")
    uplift_kg = data.get("uplift_kg")
    fuel_type = data.get("fuel_type", "JET-A1")

    if not flight_id or uplift_kg is None:
        return _error("'flight_id' and 'uplift_kg' are required.")

    # INTENTIONAL: no negative check
    entry = {
        "id": len(_FUEL_LOG) + 1,
        "flight_id": flight_id,
        "uplift_kg": uplift_kg,  # may be negative!
        "fuel_type": fuel_type,
        "timestamp": time.time(),
        "status": "PENDING",
    }
    _FUEL_LOG.append(entry)
    _audit("fuel_uplift_requested", {"flight_id": flight_id, "uplift_kg": uplift_kg})

    return _json_response({"id": entry["id"], "status": "PENDING"}, 201)


@app.route("/api/v1/fuel/log", methods=["GET"])
def get_fuel_log() -> Response:
    return _json_response(_FUEL_LOG)


# ── VULNERABILITY 4: Path traversal in charts endpoint ──────────────────────

_CHARTS_BASE = "/tmp/efb_charts"  # simulated chart storage

ALLOWED_CHART_RE = re.compile(r"^[A-Z0-9_\-]+\.(pdf|png|svg)$", re.IGNORECASE)


@app.route("/api/v1/charts/<path:chart_name>", methods=["GET"])
def get_chart(chart_name: str) -> Response:
    """
    Download a navigation chart by name.

    VULNERABILITY: Insufficient path traversal protection.
    The regex check prevents obvious '../' traversal but not encoded
    variants like '%2e%2e%2f' or null-byte injection.
    ZAP path traversal scan will detect this.
    """
    _audit("chart_requested", {"chart_name": chart_name})

    # INTENTIONAL: only basic check — URL-decoded traversal bypasses this
    if not ALLOWED_CHART_RE.match(chart_name):
        return _error(
            f"Invalid chart name: {chart_name!r}. "
            "Only alphanumeric filenames with .pdf/.png/.svg allowed.",
            400,
        )

    # In simulation, we don't serve real files
    return _json_response(
        {
            "chart_name": chart_name,
            "url": f"/static/charts/{chart_name}",
            "format": chart_name.rsplit(".", 1)[-1].upper(),
            "size_bytes": 204800,
        }
    )


# ── Status and audit ─────────────────────────────────────────────────────────


@app.route("/api/v1/status", methods=["GET"])
def get_status() -> Response:
    """
    EFB system status.
    VULNERABILITY: Exposes internal version string → fingerprinting.
    """
    return _json_response(
        {
            "efb_software": "SkyEFB",
            "version": "2.4.1-beta",  # version disclosure
            "os": "Linux 5.15.0",  # OS disclosure
            "uptime_seconds": int(time.time() % 86400),
            "flights_loaded": len(_FLIGHT_PLANS),
            "messages_queued": len(_CREW_MESSAGES),
        }
    )


@app.route("/api/v1/audit", methods=["GET"])
def get_audit_log() -> Response:
    """
    VULNERABILITY: Audit log accessible without authentication.
    Reveals all API activity including attacker's own probe requests.
    """
    return _json_response(_AUDIT_LOG[-100:])  # last 100 events


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────


def create_app() -> Flask:
    """Factory for use in tests (avoids port conflicts)."""
    return app


if __name__ == "__main__":
    port = int(os.environ.get("EFB_PORT", 5001))
    print(f"[SkyGuard EFB] Starting on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
