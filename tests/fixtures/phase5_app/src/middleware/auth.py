from fastapi import Cookie, HTTPException


def require_auth(session: str | None = Cookie(default=None)):
    if session not in ('user_a', 'user_b'):
        raise HTTPException(status_code=401)
    return session
