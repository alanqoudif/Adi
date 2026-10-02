from fastapi import HTTPException

ORDERS = {
    1: {'id': 1, 'owner': 'user_a', 'private_note': 'controlled A record'},
    2: {'id': 2, 'owner': 'user_b', 'private_note': 'controlled B record'},
}


def find_order(id: int):
    return ORDERS.get(id)


def enforce_owner(order: dict, user: str):
    if order['owner'] != user:
        raise HTTPException(status_code=403)
