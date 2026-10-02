"""Intentionally vulnerable local-only Phase 5 acceptance lab."""
from fastapi import FastAPI
from src.routes.orders import router

app = FastAPI(debug=True)
app.include_router(router)


@app.get('/')
def home():
    return {'lab': 'Adi Phase 5', 'links': ['/api/orders/1', '/api/orders-safe/1', '/api/private']}
