SENSITIVE_FIELDS = [
    "role", "admin", "isAdmin", "is_admin", "balance", "credit",
    "verified", "approved", "superuser", "permissions", "privilege"
]

SENSITIVE_PATTERNS = {
    "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "jwt": r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "private_key": r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
    "password_field": r'"password"\s*:\s*"[^"]+"',
    "secret": r'"secret"\s*:\s*"[^"]+"',
}

RATE_LIMIT_ENDPOINTS = ["login", "signin", "otp", "verify", "reset", "forgot", "password"]

REQUEST_TIMEOUT = 10
RATE_LIMIT_COUNT = 100
