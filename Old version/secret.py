import secrets

# Generate a 32-byte random secret key
secret_key = secrets.token_hex(32)
print(secret_key)
