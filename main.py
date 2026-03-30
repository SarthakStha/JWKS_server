from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import sqlite3
import datetime

hostName = "localhost"
serverPort = 8090

# Name of the DB file
DB_FILE = "totally_not_my_privateKeys.db"

# Initializing the DB
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Creating the query
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    conn.commit()
    return conn

# Generating the keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Generating the signatures
valid_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Stores the keys in the DB
def store_keys(conn):
    cursor = conn.cursor()
    now = datetime.datetime.utcnow()

    # Defining the parameter
    keys_to_store = [
        (
            valid_pem,
            int((now + datetime.timedelta(hours=1)).timestamp())   # future — valid
        ),
        (
            expired_pem,
            int((now - datetime.timedelta(hours=1)).timestamp())   # past — expired
        ),
    ]

    # Running the paramterrized query
    cursor.executemany(
        """
            INSERT INTO keys (key, exp) VALUES (?, ?)
        """, 
        keys_to_store
    )
    conn.commit()

conn = init_db()
store_keys(conn)

# numbers = private_key.private_numbers()

# Defining the Vaild & Invalid Keys
keys = {
    "valid" : {
        "kid": "goodKID", 
        "private_key": private_key, 
        "expiry": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        "pem": valid_pem,
    },
    "invalid" : {
        "kid": "expiredKID", 
        "private_key": expired_key, 
        "expiry": datetime.datetime.utcnow() - datetime.timedelta(hours=1),
        "pem": expired_pem,
    },
}


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth": 
            now = int(datetime.datetime.utcnow().timestamp())
            use_expired = 'expired' in params

            cursor = conn.cursor()
            if use_expired:
                cursor.execute("SELECT kid, key, exp FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1", (now,))
            else:
                cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (now,))

            row = cursor.fetchone()

            if not row:
                self.send_response(404)
                self.end_headers()
                return

            kid, key_blob, exp = row

            token_payload = {
                "user": "username",
                "exp": exp
            }
            headers = {"kid": str(kid)}

            try:
                encoded_jwt = jwt.encode(token_payload, key_blob, algorithm="RS256", headers=headers)
                self.send_response(200)
                self.send_header("Content-Type", "application/jwt")
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
                return
            
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            now = datetime.datetime.utcnow()
            valid_keys = [key for key in keys.values() if key["expiry"] > now]
            pub_numbers = [k["private_key"].private_numbers().public_numbers for k in valid_keys]

            jwks = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": key["kid"],
                        "n": int_to_base64(pub.n),
                        "e": int_to_base64(pub.e),
                    }
                    for key, pub in zip(valid_keys, pub_numbers)
                ]
            }

            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    # initialize the custom MyServer class
    webServer = HTTPServer((hostName, serverPort), MyServer)

    # Continue running the server indefinately until
    # The user interrupts the server.
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    
    # Close the DB connection & the webserver
    conn.close()
    webServer.server_close()
