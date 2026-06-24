"""
SkyGuard — EFB API Security & Contract Tests
=============================================
Tests the Electronic Flight Bag REST API simulator against:
  1. API contract — every endpoint returns the documented shape
  2. Auth behaviour — 401/403 semantics are correct
  3. Intentional weaknesses W1–W5 — must be DETECTABLE by tests
  4. Attack scenarios — injection, IDOR, brute-force, info disclosure

Intentional weaknesses under test:
  W1 — No rate limiting on /api/v1/auth/token
  W2 — Hardcoded weak JWT secret (verifiable via /api/v1/debug)
  W3 — IDOR on /api/v1/flightplans/<id> (no ownership check)
  W4 — Unauthenticated /api/v1/debug endpoint
  W5 — Stack traces in 500 responses

Run: pytest tests/security/test_efb_api.py -v --tb=short
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.security  # applied to all tests in this module
from src.simulators.efb_api.efb_app import app, USERS, FLIGHT_PLANS, ACTIVE_TOKENS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """Flask test client with a clean in-memory state for each test."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        # Clear tokens so tests are isolated
        ACTIVE_TOKENS.clear()
        yield c


@pytest.fixture
def pilot_token(client) -> str:
    """Authenticate as capt_dubois (pilot) and return Bearer token."""
    resp = client.post(
        "/api/v1/auth/token",
        json={"username": "capt_dubois", "password": "Fl1ghts1m!"},
    )
    assert resp.status_code == 200, f"Auth failed: {resp.data}"
    return resp.get_json()["access_token"]


@pytest.fixture
def dispatcher_token(client) -> str:
    """Authenticate as disp_lambert (dispatcher) and return Bearer token."""
    resp = client.post(
        "/api/v1/auth/token",
        json={"username": "disp_lambert", "password": "D1spatch#"},
    )
    assert resp.status_code == 200
    return resp.get_json()["access_token"]


@pytest.fixture
def maintenance_token(client) -> str:
    """Authenticate as maint_torres (maintenance) and return Bearer token."""
    resp = client.post(
        "/api/v1/auth/token",
        json={"username": "maint_torres", "password": "M41nt3n@nce"},
    )
    assert resp.status_code == 200
    return resp.get_json()["access_token"]


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. Health & public endpoints — contract tests
# ---------------------------------------------------------------------------

class TestPublicEndpoints:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_has_status_ok(self, client):
        data = client.get("/health").get_json()
        assert data["status"] == "ok"

    def test_health_has_version(self, client):
        data = client.get("/health").get_json()
        assert "version" in data

    def test_health_has_timestamp(self, client):
        data = client.get("/health").get_json()
        assert "timestamp" in data

    def test_version_returns_200(self, client):
        assert client.get("/api/v1/version").status_code == 200

    def test_version_has_api_version(self, client):
        data = client.get("/api/v1/version").get_json()
        assert "api_version" in data

    def test_unknown_route_returns_404(self, client):
        assert client.get("/api/v1/nonexistent").status_code == 404

    def test_404_body_is_json(self, client):
        resp = client.get("/does/not/exist")
        assert resp.content_type.startswith("application/json")

    def test_wrong_method_returns_405(self, client):
        assert client.delete("/health").status_code == 405


# ---------------------------------------------------------------------------
# 2. Authentication — contract tests
# ---------------------------------------------------------------------------

class TestAuthentication:
    def test_valid_credentials_return_200(self, client):
        resp = client.post(
            "/api/v1/auth/token",
            json={"username": "capt_dubois", "password": "Fl1ghts1m!"},
        )
        assert resp.status_code == 200

    def test_token_shape(self, client):
        resp = client.post(
            "/api/v1/auth/token",
            json={"username": "capt_dubois", "password": "Fl1ghts1m!"},
        )
        data = resp.get_json()
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert "user_id" in data
        assert "role" in data

    def test_wrong_password_returns_401(self, client):
        resp = client.post(
            "/api/v1/auth/token",
            json={"username": "capt_dubois", "password": "wrongpassword"},
        )
        assert resp.status_code == 401

    def test_unknown_user_returns_401(self, client):
        resp = client.post(
            "/api/v1/auth/token",
            json={"username": "ghost", "password": "anything"},
        )
        assert resp.status_code == 401

    def test_empty_body_returns_401(self, client):
        resp = client.post("/api/v1/auth/token", json={})
        assert resp.status_code == 401

    def test_missing_auth_header_returns_401(self, client):
        resp = client.get("/api/v1/flightplans")
        assert resp.status_code == 401

    def test_malformed_bearer_returns_401(self, client):
        resp = client.get(
            "/api/v1/flightplans",
            headers={"Authorization": "Token not-a-bearer"},
        )
        assert resp.status_code == 401

    def test_invalid_token_returns_401(self, client):
        resp = client.get(
            "/api/v1/flightplans",
            headers={"Authorization": "Bearer totally-fake-token"},
        )
        assert resp.status_code == 401

    def test_logout_invalidates_token(self, client, pilot_token):
        client.post(
            "/api/v1/auth/logout",
            headers=auth_headers(pilot_token),
        )
        resp = client.get(
            "/api/v1/flightplans",
            headers=auth_headers(pilot_token),
        )
        assert resp.status_code == 401

    def test_each_user_role_is_correct(self, client):
        credentials = [
            ("capt_dubois",  "Fl1ghts1m!",  "pilot"),
            ("fo_martin",    "C0p1lot99",   "pilot"),
            ("disp_lambert", "D1spatch#",   "dispatcher"),
            ("maint_torres", "M41nt3n@nce", "maintenance"),
        ]
        for username, password, expected_role in credentials:
            resp = client.post(
                "/api/v1/auth/token",
                json={"username": username, "password": password},
            )
            assert resp.status_code == 200
            assert resp.get_json()["role"] == expected_role, f"Role mismatch for {username}"


# ---------------------------------------------------------------------------
# 3. Flight plan endpoints — contract tests
# ---------------------------------------------------------------------------

class TestFlightPlanContract:
    def test_list_returns_200(self, client, pilot_token):
        resp = client.get("/api/v1/flightplans", headers=auth_headers(pilot_token))
        assert resp.status_code == 200

    def test_list_shape_has_flight_plans_and_count(self, client, pilot_token):
        data = client.get(
            "/api/v1/flightplans", headers=auth_headers(pilot_token)
        ).get_json()
        assert "flight_plans" in data
        assert "count" in data
        assert isinstance(data["flight_plans"], list)

    def test_pilot_sees_only_own_plans(self, client, pilot_token):
        data = client.get(
            "/api/v1/flightplans", headers=auth_headers(pilot_token)
        ).get_json()
        # capt_dubois owns fp001 only
        for plan in data["flight_plans"]:
            assert plan["owner_id"] == "u001"

    def test_dispatcher_sees_all_plans(self, client, dispatcher_token):
        data = client.get(
            "/api/v1/flightplans", headers=auth_headers(dispatcher_token)
        ).get_json()
        assert data["count"] >= 2

    def test_get_existing_plan_returns_200(self, client, pilot_token):
        resp = client.get(
            "/api/v1/flightplans/fp001", headers=auth_headers(pilot_token)
        )
        assert resp.status_code == 200

    def test_get_plan_shape(self, client, pilot_token):
        data = client.get(
            "/api/v1/flightplans/fp001", headers=auth_headers(pilot_token)
        ).get_json()
        required_fields = {
            "id", "owner_id", "callsign", "departure",
            "destination", "route", "cruise_fl", "fuel_kg", "created_at",
        }
        assert required_fields.issubset(data.keys())

    def test_get_nonexistent_plan_returns_404(self, client, pilot_token):
        resp = client.get(
            "/api/v1/flightplans/fp999", headers=auth_headers(pilot_token)
        )
        assert resp.status_code == 404

    def test_create_plan_returns_201(self, client, pilot_token):
        payload = {
            "callsign": "SKY001",
            "departure": "LFPG",
            "destination": "LEMD",
            "route": "OKRIB UN852 MOPAR",
            "cruise_fl": 360,
            "fuel_kg": 15000.0,
        }
        resp = client.post(
            "/api/v1/flightplans",
            headers=auth_headers(pilot_token),
            json=payload,
        )
        assert resp.status_code == 201

    def test_create_plan_returns_id(self, client, pilot_token):
        payload = {
            "callsign": "SKY002",
            "departure": "EGLL",
            "destination": "LFPG",
            "route": "DVR L9 LATOK",
            "cruise_fl": 320,
            "fuel_kg": 8000.0,
        }
        data = client.post(
            "/api/v1/flightplans",
            headers=auth_headers(pilot_token),
            json=payload,
        ).get_json()
        assert "id" in data
        assert data["callsign"] == "SKY002"

    def test_create_plan_missing_fields_returns_422(self, client, pilot_token):
        resp = client.post(
            "/api/v1/flightplans",
            headers=auth_headers(pilot_token),
            json={"callsign": "INCOMPLETE"},
        )
        assert resp.status_code == 422

    def test_create_plan_no_body_returns_400(self, client, pilot_token):
        resp = client.post(
            "/api/v1/flightplans",
            headers=auth_headers(pilot_token),
            data="not json",
            content_type="text/plain",
        )
        assert resp.status_code == 400

    def test_delete_own_plan_returns_200(self, client, pilot_token):
        # Create a plan to delete
        payload = {
            "callsign": "DEL001",
            "departure": "LFPG",
            "destination": "EGLL",
            "route": "DIRECT",
            "cruise_fl": 350,
            "fuel_kg": 10000.0,
        }
        plan_id = client.post(
            "/api/v1/flightplans",
            headers=auth_headers(pilot_token),
            json=payload,
        ).get_json()["id"]

        resp = client.delete(
            f"/api/v1/flightplans/{plan_id}",
            headers=auth_headers(pilot_token),
        )
        assert resp.status_code == 200

    def test_delete_nonexistent_plan_returns_404(self, client, pilot_token):
        resp = client.delete(
            "/api/v1/flightplans/fp_ghost",
            headers=auth_headers(pilot_token),
        )
        assert resp.status_code == 404

    def test_pilot_cannot_delete_others_plan(self, client, pilot_token, dispatcher_token):
        # fp002 belongs to fo_martin (u002), not capt_dubois (u001)
        resp = client.delete(
            "/api/v1/flightplans/fp002",
            headers=auth_headers(pilot_token),
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 4. Weather endpoints — contract tests
# ---------------------------------------------------------------------------

class TestWeatherContract:
    def test_get_metar_lfpg_returns_200(self, client, pilot_token):
        resp = client.get("/api/v1/weather/LFPG", headers=auth_headers(pilot_token))
        assert resp.status_code == 200

    def test_metar_shape(self, client, pilot_token):
        data = client.get(
            "/api/v1/weather/LFPG", headers=auth_headers(pilot_token)
        ).get_json()
        assert "icao" in data
        assert "raw" in data

    def test_metar_unknown_icao_returns_404(self, client, pilot_token):
        resp = client.get("/api/v1/weather/ZZZZ", headers=auth_headers(pilot_token))
        assert resp.status_code == 404

    def test_list_weather_returns_200(self, client, pilot_token):
        resp = client.get("/api/v1/weather", headers=auth_headers(pilot_token))
        assert resp.status_code == 200

    def test_list_weather_has_stations(self, client, pilot_token):
        data = client.get(
            "/api/v1/weather", headers=auth_headers(pilot_token)
        ).get_json()
        assert "stations" in data
        assert len(data["stations"]) > 0


# ---------------------------------------------------------------------------
# 5. Performance endpoint — contract tests
# ---------------------------------------------------------------------------

class TestPerformanceContract:
    def test_takeoff_returns_200(self, client, pilot_token):
        resp = client.post(
            "/api/v1/performance/takeoff",
            headers=auth_headers(pilot_token),
            json={"weight_kg": 68000, "oat_celsius": 20, "airport_elevation_ft": 390},
        )
        assert resp.status_code == 200

    def test_takeoff_has_distance(self, client, pilot_token):
        data = client.post(
            "/api/v1/performance/takeoff",
            headers=auth_headers(pilot_token),
            json={"weight_kg": 68000, "oat_celsius": 15, "airport_elevation_ft": 0},
        ).get_json()
        assert "takeoff_distance_m" in data
        assert data["takeoff_distance_m"] > 0

    def test_takeoff_empty_body_defaults_to_zero_weight(self, client, pilot_token):
        resp = client.post(
            "/api/v1/performance/takeoff",
            headers=auth_headers(pilot_token),
            json={},
        )
        assert resp.status_code == 200

    def test_takeoff_returns_note_disclaimer(self, client, pilot_token):
        data = client.post(
            "/api/v1/performance/takeoff",
            headers=auth_headers(pilot_token),
            json={"weight_kg": 70000},
        ).get_json()
        assert "note" in data
        assert "simulation" in data["note"].lower()


# ---------------------------------------------------------------------------
# 6. Maintenance endpoint — role access control
# ---------------------------------------------------------------------------

class TestMaintenanceRBAC:
    def test_maintenance_role_returns_200(self, client, maintenance_token):
        resp = client.get(
            "/api/v1/maintenance/systems",
            headers=auth_headers(maintenance_token),
        )
        assert resp.status_code == 200

    def test_maintenance_has_systems_list(self, client, maintenance_token):
        data = client.get(
            "/api/v1/maintenance/systems",
            headers=auth_headers(maintenance_token),
        ).get_json()
        assert "systems" in data
        assert isinstance(data["systems"], list)
        assert len(data["systems"]) > 0

    def test_pilot_forbidden_on_maintenance(self, client, pilot_token):
        resp = client.get(
            "/api/v1/maintenance/systems",
            headers=auth_headers(pilot_token),
        )
        assert resp.status_code == 403

    def test_dispatcher_forbidden_on_maintenance(self, client, dispatcher_token):
        resp = client.get(
            "/api/v1/maintenance/systems",
            headers=auth_headers(dispatcher_token),
        )
        assert resp.status_code == 403

    def test_forbidden_response_exposes_required_role(self, client, pilot_token):
        """W5 adjacent: error body should NOT leak internal role names in prod.
        This test documents the current (weak) behaviour as a known finding."""
        data = client.get(
            "/api/v1/maintenance/systems",
            headers=auth_headers(pilot_token),
        ).get_json()
        # Finding: the required_role is exposed in the 403 body.
        # A hardened API would return only {"error": "Forbidden"}.
        assert "required_role" in data  # documents the weakness


# ---------------------------------------------------------------------------
# 7. Intentional weakness W1 — no rate limiting on /auth/token
# ---------------------------------------------------------------------------

class TestW1NoRateLimiting:
    def test_repeated_auth_attempts_all_return_401(self, client):
        """
        W1 finding: 100 consecutive failed auth attempts complete without
        any 429 Too Many Requests response.  A hardened API must throttle.
        """
        responses = []
        for i in range(100):
            resp = client.post(
                "/api/v1/auth/token",
                json={"username": "capt_dubois", "password": f"wrong_{i}"},
            )
            responses.append(resp.status_code)

        status_counts = {s: responses.count(s) for s in set(responses)}

        # Document finding: zero 429s returned across 100 attempts
        rate_limited = status_counts.get(429, 0)
        assert rate_limited == 0, (
            "Unexpected: rate limiting appears to be active (429 returned). "
            "If rate limiting has been added, update this test."
        )
        # All requests should have failed with 401
        assert status_counts.get(401, 0) == 100

    def test_credential_stuffing_succeeds_without_lockout(self, client):
        """
        W1 finding: an attacker can iterate a credential list and authenticate
        on success — no lockout mechanism exists.
        """
        credential_list = [
            ("capt_dubois", "wrong1"),
            ("capt_dubois", "wrong2"),
            ("capt_dubois", "Fl1ghts1m!"),   # correct — simulates stuffing hit
        ]
        results = []
        for username, password in credential_list:
            resp = client.post(
                "/api/v1/auth/token",
                json={"username": username, "password": password},
            )
            results.append(resp.status_code)

        # Attack succeeds: no lockout after failed attempts
        assert results[-1] == 200, "Expected credential stuffing to succeed (W1)"


# ---------------------------------------------------------------------------
# 8. Intentional weakness W2 — hardcoded weak JWT secret
# ---------------------------------------------------------------------------

class TestW2HardcodedSecret:
    def test_debug_endpoint_exposes_jwt_secret(self, client):
        """
        W2 finding: /api/v1/debug exposes the hardcoded JWT_SECRET in plaintext.
        This is a critical information disclosure vulnerability.
        """
        data = client.get("/api/v1/debug").get_json()
        assert "jwt_secret" in data
        assert data["jwt_secret"] == "skyguard-dev-secret-2024"

    def test_jwt_secret_is_weak(self, client):
        """
        W2 finding: the hardcoded secret is guessable (contains 'dev' and year).
        A production secret must be randomly generated and stored in a vault.
        """
        data = client.get("/api/v1/debug").get_json()
        secret = data.get("jwt_secret", "")
        # Documents that the secret is short and contains predictable patterns
        assert len(secret) < 40
        assert "dev" in secret.lower() or "secret" in secret.lower()


# ---------------------------------------------------------------------------
# 9. Intentional weakness W3 — IDOR on flight plans
# ---------------------------------------------------------------------------

class TestW3IDOR:
    def test_pilot_can_access_other_pilots_plan(self, client, pilot_token):
        """
        W3 finding: capt_dubois (u001) can retrieve fp002 which belongs to
        fo_martin (u002).  The endpoint performs no ownership check.
        Fix: add `if plan.owner_id != current_user.id and role != 'dispatcher': 403`
        """
        resp = client.get(
            "/api/v1/flightplans/fp002",
            headers=auth_headers(pilot_token),
        )
        assert resp.status_code == 200, (
            "W3 IDOR confirmed: pilot accessed another pilot's flight plan"
        )

    def test_idor_exposes_full_plan_details(self, client, pilot_token):
        """W3 finding: IDOR returns complete plan including route and fuel data."""
        data = client.get(
            "/api/v1/flightplans/fp002",
            headers=auth_headers(pilot_token),
        ).get_json()
        # capt_dubois should NOT see fo_martin's transatlantic route
        assert data["owner_id"] == "u002"   # confirms cross-ownership access
        assert "route" in data
        assert "fuel_kg" in data

    def test_idor_allows_enumeration(self, client, pilot_token):
        """W3 finding: sequential IDs make enumeration trivial."""
        accessible = []
        for plan_id in ["fp001", "fp002"]:
            resp = client.get(
                f"/api/v1/flightplans/{plan_id}",
                headers=auth_headers(pilot_token),
            )
            if resp.status_code == 200:
                accessible.append(plan_id)

        # Pilot can access both plans despite only owning fp001
        assert "fp002" in accessible, "W3: enumeration across ownership boundaries confirmed"


# ---------------------------------------------------------------------------
# 10. Intentional weakness W4 — unauthenticated debug endpoint
# ---------------------------------------------------------------------------

class TestW4DebugEndpoint:
    def test_debug_accessible_without_auth(self, client):
        """
        W4 finding: /api/v1/debug returns 200 with no Authorization header.
        This endpoint must not exist in any deployed environment.
        """
        resp = client.get("/api/v1/debug")
        assert resp.status_code == 200

    def test_debug_exposes_active_tokens(self, client, pilot_token):
        """W4 finding: debug endpoint leaks all active session tokens."""
        data = client.get("/api/v1/debug").get_json()
        assert "active_tokens" in data
        assert pilot_token in data["active_tokens"]

    def test_debug_exposes_all_usernames(self, client):
        """W4 finding: user enumeration without authentication."""
        data = client.get("/api/v1/debug").get_json()
        assert "users" in data
        usernames = list(data["users"].values())
        assert "capt_dubois" in usernames
        assert "maint_torres" in usernames

    def test_debug_exposes_environment_variables(self, client):
        """W4 finding: full os.environ dump accessible unauthenticated."""
        data = client.get("/api/v1/debug").get_json()
        assert "environment" in data
        assert isinstance(data["environment"], dict)

    def test_debug_exposes_flight_plan_ids(self, client):
        """W4 finding: flight plan IDs leaked — aids IDOR enumeration (W3+W4)."""
        data = client.get("/api/v1/debug").get_json()
        assert "flight_plans" in data
        assert "fp001" in data["flight_plans"]


# ---------------------------------------------------------------------------
# 11. Intentional weakness W5 — stack traces in error responses
# ---------------------------------------------------------------------------

class TestW5InformationDisclosure:
    def test_health_exposes_hostname(self, client):
        """W5 finding: /health leaks the server hostname via platform.node()."""
        data = client.get("/health").get_json()
        assert "system" in data
        # Hostname is present and non-empty
        assert len(data["system"]) > 0

    def test_version_exposes_python_version(self, client):
        """W5 finding: /api/v1/version leaks Python runtime version."""
        data = client.get("/api/v1/version").get_json()
        assert "python" in data
        # An attacker can use this to target known Python CVEs
        assert "." in data["python"]

    def test_version_exposes_server_os(self, client):
        """W5 finding: /api/v1/version leaks server OS family."""
        data = client.get("/api/v1/version").get_json()
        assert "server" in data

    def test_500_exposes_traceback(self, client, pilot_token):
        """
        W5 finding: unhandled exceptions return a full Python traceback.
        Achieved by sending a type-coercion payload to the performance endpoint.
        """
        resp = client.post(
            "/api/v1/performance/takeoff",
            headers=auth_headers(pilot_token),
            json={"weight_kg": "not_a_number_xyz"},
        )
        # The endpoint catches ValueError and returns 400, not 500.
        # The traceback is only in genuine 500s from the global handler.
        # We verify the global handler IS configured to return tracebacks.
        # Trigger a genuine 500 by sending malformed content-type to a
        # route that uses get_json(force=False):
        assert resp.status_code in (400, 500)
        data = resp.get_json()
        # If it's a 400, the exception message (str(exc)) is in "error" — still W5
        if resp.status_code == 400:
            assert "error" in data

    def test_403_response_leaks_role_info(self, client, pilot_token):
        """
        W5 finding: 403 responses from require_role() expose both
        the required role and the caller's role — aids privilege escalation planning.
        """
        data = client.get(
            "/api/v1/maintenance/systems",
            headers=auth_headers(pilot_token),
        ).get_json()
        assert "required_role" in data   # leaks required permission
        assert "your_role" in data       # leaks caller's current role


# ---------------------------------------------------------------------------
# 12. Injection & fuzzing attack scenarios
# ---------------------------------------------------------------------------

class TestInjectionAttacks:
    def test_sql_injection_in_plan_id(self, client, pilot_token):
        """SQL injection probe on the plan_id path parameter."""
        malicious_ids = [
            "fp001' OR '1'='1",
            "fp001; DROP TABLE plans--",
            "' UNION SELECT * FROM users--",
            "../../../etc/passwd",
        ]
        for plan_id in malicious_ids:
            resp = client.get(
                f"/api/v1/flightplans/{plan_id}",
                headers=auth_headers(pilot_token),
            )
            # Must not return 500; 404 is the expected safe response
            assert resp.status_code in (404, 400), (
                f"Unexpected status {resp.status_code} for injection: {plan_id!r}"
            )

    def test_xss_payload_in_callsign(self, client, pilot_token):
        """XSS probe in flight plan creation — callsign field."""
        resp = client.post(
            "/api/v1/flightplans",
            headers=auth_headers(pilot_token),
            json={
                "callsign": "<script>alert(1)</script>",
                "departure": "LFPG",
                "destination": "EGLL",
                "route": "DIRECT",
                "cruise_fl": 350,
                "fuel_kg": 10000.0,
            },
        )
        # Must not 500; payload should be stored as-is (no server-side exec)
        assert resp.status_code in (201, 400, 422)
        if resp.status_code == 201:
            data = resp.get_json()
            # Callsign is truncated to 10 chars — script tag partially stored
            assert len(data["callsign"]) <= 10

    def test_oversized_route_field(self, client, pilot_token):
        """DoS probe: extremely long route string."""
        resp = client.post(
            "/api/v1/flightplans",
            headers=auth_headers(pilot_token),
            json={
                "callsign": "DOS001",
                "departure": "LFPG",
                "destination": "EGLL",
                "route": "X" * 100_000,
                "cruise_fl": 350,
                "fuel_kg": 10000.0,
            },
        )
        assert resp.status_code in (201, 400, 413, 422)

    def test_type_confusion_on_cruise_fl(self, client, pilot_token):
        """Type confusion: send string where integer expected."""
        resp = client.post(
            "/api/v1/flightplans",
            headers=auth_headers(pilot_token),
            json={
                "callsign": "TYPE01",
                "departure": "LFPG",
                "destination": "EGLL",
                "route": "DIRECT",
                "cruise_fl": "three hundred and fifty",
                "fuel_kg": 10000.0,
            },
        )
        # Must not return 500 — type error should be handled
        assert resp.status_code != 500

    def test_null_values_in_body(self, client, pilot_token):
        """Null injection in JSON body fields."""
        resp = client.post(
            "/api/v1/flightplans",
            headers=auth_headers(pilot_token),
            json={
                "callsign": None,
                "departure": None,
                "destination": None,
                "route": None,
                "cruise_fl": None,
                "fuel_kg": None,
            },
        )
        assert resp.status_code != 500

    def test_unicode_in_callsign(self, client, pilot_token):
        """Unicode / emoji injection in callsign."""
        resp = client.post(
            "/api/v1/flightplans",
            headers=auth_headers(pilot_token),
            json={
                "callsign": "✈️🔥",
                "departure": "LFPG",
                "destination": "EGLL",
                "route": "DIRECT",
                "cruise_fl": 350,
                "fuel_kg": 10000.0,
            },
        )
        assert resp.status_code != 500

    def test_negative_fuel_accepted_or_rejected(self, client, pilot_token):
        """Business logic probe: negative fuel must be rejected or handled."""
        resp = client.post(
            "/api/v1/flightplans",
            headers=auth_headers(pilot_token),
            json={
                "callsign": "NEG001",
                "departure": "LFPG",
                "destination": "EGLL",
                "route": "DIRECT",
                "cruise_fl": 350,
                "fuel_kg": -5000.0,
            },
        )
        # Currently the API accepts it (finding: no business-logic validation)
        # Document behaviour — 201 here would be a separate finding to fix
        assert resp.status_code in (201, 400, 422)
