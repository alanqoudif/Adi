import ast

from fastapi import APIRouter, Depends, HTTPException, Response

from src.middleware.auth import require_auth
from src.services.orders import enforce_owner, find_order

router = APIRouter(prefix='/api')


@router.post('/login')
def login(username: str, response: Response):
    if username not in ('user_a', 'user_b'):
        raise HTTPException(status_code=403)
    response.set_cookie('session', username, httponly=True, samesite='strict')
    return {'user': username}


@router.get('/orders/{id}')
def get_order(id: int, user: str = Depends(require_auth)):
    order = find_order(id)
    if order is None:
        raise HTTPException(status_code=404)
    # Authentication is enforced, but ownership is intentionally absent.
    return order


@router.get('/orders-safe/{id}')
def get_order_safe(id: int, user: str = Depends(require_auth)):
    order = find_order(id)
    if order is None:
        raise HTTPException(status_code=404)
    enforce_owner(order, user)
    return order


@router.get('/private')
def private(user: str = Depends(require_auth)):
    return {'user': user, 'protected': True}


@router.get('/parse-literal')
def parse_literal():
    # Semgrep flags this broad parsing rule; AST literal parsing cannot execute code.
    return ast.literal_eval('{"safe": 1}')
