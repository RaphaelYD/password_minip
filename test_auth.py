import os
import sqlite3
import pytest

import auth_sqlite as main

# On importe les fonctions du projet principal

TEST_DB = "test_auth.db"

@pytest.fixture(autouse=True)
def setup_db(monkeypatch):
    """
    Avant chaque test :
    - utiliser une base SQLite de test
    - initialiser la table users
    Après chaque test :
    - supprimer le fichier DB
    """
    monkeypatch.setattr(main, "DB_PATH", TEST_DB)
    main.init_db()

    yield  # Exécution des tests

    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)


def test_create_user_and_login():
    password = "StrongPass123!"
    main.create_user("alice", main.hash_password_bcrypt(password))

    user = main.get_user("alice")
    assert user is not None
    assert main.verify_password_bcrypt(user["password_hash"], password)


def test_wrong_password_attempts():
    password = "MyPass123!"
    main.create_user("bob", main.hash_password_bcrypt(password))

    user = main.get_user("bob")
    assert main.verify_password_bcrypt(user["password_hash"], "wrong") is False


def test_lockout_after_three_failures():
    password = "LockMe123!"
    main.create_user("charlie", main.hash_password_bcrypt(password))

    # 3 tentatives ratées
    for _ in range(main.MAX_ATTEMPTS):
        user = main.get_user("charlie")
        assert main.verify_password_bcrypt(user["password_hash"], "badpass") is False
        main.update_user_fields("charlie", attempts=user["attempts"] + 1)

    # Appliquer lockout
    user = main.get_user("charlie")
    duration = main.apply_lockout(user)
    assert duration > 0

    # Vérifier que le compte est verrouillé
    locked_user = main.get_user("charlie")
    assert main.is_locked(locked_user) is True


def test_reset_user():
    password = "Reset123!"
    main.create_user("diana", main.hash_password_bcrypt(password))

    # Simuler 2 échecs + lockout
    main.update_user_fields("diana", attempts=2, lockout_until=9999999999, lockout_cycles=1)

    user = main.get_user("diana")
    assert user["attempts"] == 2
    assert user["lockout_cycles"] == 1

    # Reset
    main.update_user_fields("diana", attempts=0, lockout_until=0, lockout_cycles=0)

    reset_user = main.get_user("diana")
    assert reset_user["attempts"] == 0
    assert reset_user["lockout_until"] == 0
    assert reset_user["lockout_cycles"] == 0


# -------------------- Tests supplémentaires : password_strength --------------------

def test_password_strength_very_weak():
    score, cat, tips = main.password_strength("123")
    assert cat == "Very Weak"
    assert score == 0 or score == 1
    assert "Use at least 8 characters" in tips

def test_password_strength_weak():
    score, cat, tips = main.password_strength("password")
    assert cat in ("Very Weak", "Weak")
    assert "Avoid common passwords" in tips

def test_password_strength_medium():
    score, cat, tips = main.password_strength("Password123")
    assert cat == "Medium"

def test_password_strength_strong():
    score, cat, tips = main.password_strength("Str0ng!Pass123")
    assert cat == "Strong"
    assert score >= 4
