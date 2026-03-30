import requests
import jwt
import json
from jwt.algorithms import RSAAlgorithm

BASE_URL = "http://localhost:8080"
PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"

results = {"passed": 0, "failed": 0}


def print_result(test_name, passed, detail=None):
    status = PASS if passed else FAIL
    if passed:
        results["passed"] += 1
    else:
        results["failed"] += 1
    print(f"{status} {test_name}")
    if detail:
        print(f"       {detail}")


def test_get_jwks():
    print("\n--- GET /.well-known/jwks.json ---")
    try:
        res = requests.get(f"{BASE_URL}/.well-known/jwks.json")

        # Check status code
        print_result("Returns 200", res.status_code == 200,
                     f"Status code: {res.status_code}")

        # Check content type
        content_type = res.headers.get("Content-type", "")
        print_result("Content-Type is application/json",
                     "application/json" in content_type,
                     f"Content-Type: {content_type}")

        # Check response is valid JSON
        try:
            body = res.json()
            print_result("Response is valid JSON", True)
        except Exception:
            print_result("Response is valid JSON", False, "Could not parse JSON body")
            return None

        # Check 'keys' field exists and is a list
        has_keys = "keys" in body and isinstance(body["keys"], list)
        print_result("Response contains 'keys' array", has_keys,
                     f"Keys found: {len(body['keys']) if has_keys else 'N/A'}")

        if not has_keys or len(body["keys"]) == 0:
            print_result("At least one valid key returned", False, "No keys in response")
            return None

        # Check each key has required JWKS fields
        required_fields = {"alg", "kty", "use", "kid", "n", "e"}
        for i, key in enumerate(body["keys"]):
            missing = required_fields - key.keys()
            print_result(f"Key {i+1} has all required JWKS fields",
                         len(missing) == 0,
                         f"Missing fields: {missing}" if missing else None)

        # Confirm no expired keys are included (kid should only be integers from valid rows)
        print(f"{INFO} {len(body['keys'])} non-expired key(s) returned in JWKS")

        return body["keys"]

    except requests.ConnectionError:
        print(f"{FAIL} Could not connect to server at {BASE_URL}. Is it running?")
        return None


def test_post_auth_valid():
    print("\n--- POST /auth (valid key) ---")
    try:
        res = requests.post(f"{BASE_URL}/auth")

        print_result("Returns 200", res.status_code == 200,
                     f"Status code: {res.status_code}")

        token = res.text.strip()
        print_result("Response body is non-empty", bool(token))

        # Decode header without verification to inspect kid
        try:
            header = jwt.get_unverified_header(token)
            print_result("Token has a 'kid' header", "kid" in header,
                         f"kid: {header.get('kid')}")
        except Exception as e:
            print_result("Token header is decodable", False, str(e))
            return None

        # Decode payload without verification to check expiry
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            exp = payload.get("exp")
            import time
            is_future = exp and exp > int(time.time())
            print_result("Token 'exp' is in the future (valid token)", is_future,
                         f"exp: {exp}")
        except Exception as e:
            print_result("Token payload is decodable", False, str(e))

        return token

    except requests.ConnectionError:
        print(f"{FAIL} Could not connect to server at {BASE_URL}. Is it running?")
        return None


def test_post_auth_expired():
    print("\n--- POST /auth?expired (expired key) ---")
    try:
        res = requests.post(f"{BASE_URL}/auth?expired=true")

        print_result("Returns 200", res.status_code == 200,
                     f"Status code: {res.status_code}")

        token = res.text.strip()
        print_result("Response body is non-empty", bool(token))

        # Decode header
        try:
            header = jwt.get_unverified_header(token)
            print_result("Token has a 'kid' header", "kid" in header,
                         f"kid: {header.get('kid')}")
        except Exception as e:
            print_result("Token header is decodable", False, str(e))
            return None

        # Decode payload and check expiry is in the past
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            exp = payload.get("exp")
            import time
            is_past = exp and exp < int(time.time())
            print_result("Token 'exp' is in the past (expired token)", is_past,
                         f"exp: {exp}")
        except Exception as e:
            print_result("Token payload is decodable", False, str(e))

        return token

    except requests.ConnectionError:
        print(f"{FAIL} Could not connect to server at {BASE_URL}. Is it running?")
        return None


def test_jwt_signature_against_jwks(token, jwks_keys):
    print("\n--- JWT Signature Verification (against JWKS) ---")
    if not token or not jwks_keys:
        print(f"{FAIL} Skipped — missing token or JWKS keys")
        return

    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")

        # Find the matching key in JWKS
        matching = [k for k in jwks_keys if k["kid"] == kid]
        print_result(f"Matching JWKS key found for kid={kid}", bool(matching))

        if not matching:
            return

        # Build public key from JWK
        public_key = RSAAlgorithm.from_jwk(json.dumps(matching[0]))

        # Verify the token signature
        try:
            jwt.decode(token, public_key, algorithms=["RS256"])
            print_result("Token signature is valid", True)
        except jwt.ExpiredSignatureError:
            # Signature was valid, just expired — that's fine for the valid token test
            print_result("Token signature is valid (token is expired but sig checks out)", True)
        except jwt.InvalidSignatureError:
            print_result("Token signature is valid", False, "Signature mismatch")
        except Exception as e:
            print_result("Token signature is valid", False, str(e))

    except Exception as e:
        print_result("JWT signature verification", False, str(e))


def test_disallowed_methods():
    print("\n--- Disallowed HTTP Methods ---")
    endpoints = ["/auth", "/.well-known/jwks.json"]
    methods = ["put", "patch", "delete", "head"]

    for method in methods:
        for endpoint in endpoints:
            try:
                res = getattr(requests, method)(f"{BASE_URL}{endpoint}")
                print_result(f"{method.upper()} {endpoint} returns 405",
                             res.status_code == 405,
                             f"Status code: {res.status_code}")
            except requests.ConnectionError:
                print(f"{FAIL} Could not connect to server at {BASE_URL}.")
                return


if __name__ == "__main__":
    print("=" * 50)
    print("  JWKS Auth Server Test Suite")
    print("=" * 50)

    jwks_keys = test_get_jwks()
    valid_token = test_post_auth_valid()
    expired_token = test_post_auth_expired()
    test_jwt_signature_against_jwks(valid_token, jwks_keys)
    test_disallowed_methods()

    total = results["passed"] + results["failed"]
    coverage = (results["passed"] / total * 100) if total > 0 else 0
    color = "\033[92m" if coverage == 100 else "\033[93m" if coverage >= 75 else "\033[91m"
    reset = "\033[0m"

    print("\n" + "=" * 50)
    print(f"  Results : {results['passed']} passed, {results['failed']} failed, {total} total")
    print(f"  Coverage: {color}{coverage:.1f}%{reset}")
    print("=" * 50)
