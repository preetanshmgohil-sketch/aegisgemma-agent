"""Deliberately vulnerable sample app — for demoing AegisGemma only.

Every issue here is intentional. Do not deploy this.
"""

import os
import subprocess

import sqlite3

DB_PASSWORD = "s3cr3t-production-password"

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter()


@router.get("/users/{user_id}")
def get_user(user_id: int):
    """No auth check — BOLA/IDOR."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))
    return cursor.fetchall()


@router.post("/run")
def run_command(command: str):
    """Command injection via os.system."""
    os.system("echo " + command)
    return {"status": "ok"}


@router.get("/exec")
def evaluate(expression: str):
    """Code injection via eval."""
    return {"result": eval(expression)}


@router.get("/backup")
def backup():
    """Hardcoded credentials + subprocess with shell=True."""
    subprocess.run(f"pg_dump -U admin -p {DB_PASSWORD}", shell=True)
    return {"bucket": AWS_ACCESS_KEY}


@router.get("/search")
def search(term: str):
    """SQL injection via string formatting."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE name = '%s'" % term)
    return cursor.fetchall()
