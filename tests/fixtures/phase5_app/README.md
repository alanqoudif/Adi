# Phase 5 local lab

Intentionally vulnerable. Bind only to 127.0.0.1. Two authorized identities:
user_a owns object 1; user_b owns object 2. The orders route omits ownership;
the orders-safe route uses a service guard. All credentials are fake.
The npm manifest is synthetic dependency/advisory test data, not a real CVE.

From this directory run `python -m uvicorn app:app --host 127.0.0.1 --port 8765`.
