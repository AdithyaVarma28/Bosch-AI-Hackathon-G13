#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${1:-mini-shop}"

# Remove existing fixture dir if present
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"

git init -b main
git config user.name "Guardian Tester"
git config user.email "guardian-tester@example.com"

# --- Commit 1: Baseline ---
mkdir -p app/api app/payments app/config tests .github/workflows

cat << 'EOF' > README.md
# Mini Shop
A mock e-commerce backend service for testing Software Supply Chain Guardian.
EOF

cat << 'EOF' > app/__init__.py
# Mini shop app package
EOF

cat << 'EOF' > app/api/routes.py
from flask import Flask, request, jsonify
from app.payments.service import charge

app = Flask(__name__)

@app.post("/checkout")
def checkout():
    data = request.json or {}
    result = charge(data.get("amount", 0))
    return jsonify({"status": "success", "charge": result})
EOF

cat << 'EOF' > app/payments/client.py
import os
import stripe

def get_client():
    api_key = os.environ["STRIPE_KEY"]
    stripe.api_key = api_key
    return stripe
EOF

cat << 'EOF' > app/payments/service.py
from app.payments.client import get_client
from app.models import Order

def charge(amount):
    client = get_client()
    charge_resp = client.Charge.create(amount=amount, currency="usd")
    return charge_resp
EOF

cat << 'EOF' > app/models.py
class Base:
    pass

class Order(Base):
    __tablename__ = "orders"
    def __init__(self, id, amount):
        self.id = id
        self.amount = amount
EOF

cat << 'EOF' > app/config/load.py
import yaml

def load_settings(path="settings.yaml"):
    with open(path, "r") as f:
        return yaml.load(f, Loader=yaml.Loader)
EOF

cat << 'EOF' > tests/test_api.py
def test_placeholder():
    assert True
EOF

cat << 'EOF' > requirements.txt
Flask==3.0.0
stripe==5.4.0
SQLAlchemy==2.0.20
PyYAML==5.4.1
requests==2.31.0
EOF

cat << 'EOF' > requirements-dev.txt
pytest==8.0.0
EOF

cat << 'EOF' > Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["flask", "run"]
EOF

cat << 'EOF' > docker-compose.yml
services:
  web:
    build: .
    ports:
      - "5000:5000"
    depends_on:
      - db
  db:
    image: postgres:16
    ports:
      - "5432:5432"
EOF

cat << 'EOF' > .github/workflows/ci.yml
name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: pytest
        env:
          TEST_TOKEN: ${{ secrets.SUPER_SECRET_KEY }}
EOF

git add .
git commit -m "Initial baseline commit for mini-shop"

# --- Commit 2: Added analytics, colorama, and PyYAML bump ---
mkdir -p app/utils

cat << 'EOF' > app/utils/helpers.py
import requests

def send_event(event_name, data):
    url = "https://analytics.external-service.com/collect"
    return requests.post(url, json={"event": event_name, "data": data})
EOF

cat << 'EOF' > app/api/routes.py
from flask import Flask, request, jsonify
from app.payments.service import charge
from app.utils.helpers import send_event

app = Flask(__name__)

@app.post("/checkout")
def checkout():
    data = request.json or {}
    result = charge(data.get("amount", 0))
    send_event("checkout_completed", result)
    return jsonify({"status": "success", "charge": result})
EOF

cat << 'EOF' > requirements.txt
Flask==3.0.0
stripe==5.4.0
SQLAlchemy==2.0.20
PyYAML==6.0.1
requests==2.31.0
colorama==0.4.6
EOF

cat << 'EOF' > .env.example
STRIPE_KEY=your_stripe_key_here
DATABASE_URL=postgres://user:pass@localhost:5432/shop
EOF

git add .
git commit -m "Add analytics tracking, colorama, and bump PyYAML"

echo "mini-shop fixture created successfully at $TARGET_DIR with 2 commits."
