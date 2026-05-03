from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.kdf.pbkdf2 import PBKDF2
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import sqlite3
import datetime
import os
import secrets
import uuid
import argon2


# Initializing the hostname, serverport & AES keys
hostName = "localhost"
serverPort = 8090

# Load the encryption key from environment variable
NOT_MY_KEY = os.getenv("NOT_MY_KEY")
if not NOT_MY_KEY:
    raise ValueError("NOT_MY_KEY environment variable is required for encryption")

# Derive a 32-byte key from NOT_MY_KEY using PBKDF2
def derive_key(master_key: str) -> bytes:
    salt = b'jwks_server_salt'  
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(master_key.encode())

ENCRYPTION_KEY = derive_key(NOT_MY_KEY)

# Name of the DB file
DB_FILE = "totally_not_my_privateKeys.db"

# password hasher configuration
password_hasher = argon2.PasswordHasher(
    time_cost=2,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    encoding='utf-8'
)

# Encryption and Decryption Functions
# Format nonce (12 bytes) + tag (16 bytes) + ciphertext
def encrypt_private_key(key_data: bytes) -> bytes:
    cipher = AESGCM(ENCRYPTION_KEY)
    nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
    ciphertext = cipher.encrypt(nonce, key_data, None)
    # Prepend nonce to ciphertext for storage
    return nonce + ciphertext

def decrypt_private_key(encrypted_data: bytes) -> bytes:
    cipher = AESGCM(ENCRYPTION_KEY)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return cipher.decrypt(nonce, ciphertext, None)

# DB Tables Initializer function
def init_table():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # keys table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)

    # users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    """)

    # auth_logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,  
            FOREIGN KEY(user_id) REFERENCES users(id)
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

    # Encrypt the private keys
    encrypted_valid_pem = encrypt_private_key(valid_pem)
    encrypted_expired_pem = encrypt_private_key(expired_pem)

    # Defining the parameter
    keys_to_store = [
        (
            encrypted_valid_pem,
            int((now + datetime.timedelta(hours=1)).timestamp())   # future — valid
        ),
        (
            encrypted_expired_pem,
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

# initializing the DB tables
conn = init_table()
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

# Generate password using UUIDv4
def generate_password() -> str:
    return str(uuid.uuid4())

# hashing the password using argon2 
def hash_password(password: str) -> str:
    return password_hasher.hash(password)

# Custom class definition 
# base properties inherited from BaseHTTPRequestHandler
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
        
        if parsed_path.path == "/register":
            # Handle user registration
            try:
                # Read the request body
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8')
                
                # Parse JSON
                request_data = json.loads(body)
                username = request_data.get('username')
                email = request_data.get('email')
                
                # Validate input
                if not username or not email:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    error_response = json.dumps({
                        "error": "Both username and email are required"
                    })
                    self.wfile.write(bytes(error_response, "utf-8"))
                    return
                
                # Generate & hash the password
                password = generate_password()
                password_hash = hash_password(password)
                
                # Store in database
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash, email)
                    VALUES (?, ?, ?)
                    """,
                    (username, password_hash, email)
                )
                conn.commit()
                
                # Return success response with generated password
                self.send_response(201)  # CREATED
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                response = json.dumps({"password": password})
                self.wfile.write(bytes(response, "utf-8"))
                return
            
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                error_response = json.dumps({"error": str(e)})
                self.wfile.write(bytes(error_response, "utf-8"))
                return
        
        elif parsed_path.path == "/auth": 
            try:
                # Read the request body
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode('utf-8')
                request_data = json.loads(body)
                username = request_data.get('username')
                
                if not username:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(bytes(json.dumps({"error": "Username is required"}), "utf-8"))
                    return
                
                # Get user ID and log authentication request
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                user_row = cursor.fetchone()
                
                if not user_row:
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(bytes(json.dumps({"error": "User not found"}), "utf-8"))
                    return
                
                user_id = user_row[0]
                client_ip = self.client_address[0]
                
                # Log the authentication request
                cursor.execute(
                    "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
                    (client_ip, user_id)
                )
                conn.commit()
                
                # Get the key for token generation
                now = int(datetime.datetime.utcnow().timestamp())
                use_expired = 'expired' in params
                
                if use_expired:
                    cursor.execute("SELECT kid, key, exp FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1", (now,))
                else:
                    cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (now,))

                row = cursor.fetchone()
                if not row:
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(bytes(json.dumps({"error": "No suitable key found"}), "utf-8"))
                    return

                kid, encrypted_key_blob, exp = row
                key_blob = decrypt_private_key(encrypted_key_blob)

                token_payload = {"user": username, "exp": exp}
                headers = {"kid": str(kid)}

                encoded_jwt = jwt.encode(token_payload, key_blob, algorithm="RS256", headers=headers)
                self.send_response(200)
                self.send_header("Content-Type", "application/jwt")
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(json.dumps({"error": str(e)}), "utf-8"))
                return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        # initial packet path filter
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            now = int(datetime.datetime.utcnow().timestamp())

            cursor = conn.cursor()

            # Reading only valid keys from the DB
            cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))
            rows = cursor.fetchall()

            # Creating the jwks response for the private keys
            jwks_keys = []
            for kid, key_blob in rows:
                try:
                    # Decrypt the private key
                    decrypted_key_blob = decrypt_private_key(key_blob)
                    loaded_key = serialization.load_pem_private_key(decrypted_key_blob, password=None)
                    pub_numbers = loaded_key.private_numbers().public_numbers
                    jwks_keys.append({
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": str(kid),
                        "n": int_to_base64(pub_numbers.n),
                        "e": int_to_base64(pub_numbers.e),
                    })
                except Exception as e:
                    # Log error but continue processing other keys
                    continue

            self.wfile.write(bytes(json.dumps({"keys": jwks_keys}), "utf-8"))
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
