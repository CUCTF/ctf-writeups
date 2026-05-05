import os
import sqlite3

from flask import current_app, g
from werkzeug.security import generate_password_hash


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(current_app.config["DB_PATH"])
    db.row_factory = sqlite3.Row
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            checklist TEXT NOT NULL,
            is_public INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );
        """
    )

    admin = db.execute("SELECT id FROM users WHERE username = ?", ("dispatcher",)).fetchone()
    if admin is None:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (
                "dispatcher",
                generate_password_hash(os.environ.get("RELAYBOARD_ADMIN_PASSWORD", "dispatch-only")),
                "admin",
            ),
        )
        admin_id = db.execute(
            "SELECT id FROM users WHERE username = ?",
            ("dispatcher",),
        ).fetchone()["id"]
        db.execute(
            """
            INSERT INTO packets (owner_id, title, body, checklist, is_public)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                admin_id,
                "Night Dispatch Master Packet",
                (
                    "This packet is reserved for the overnight coordinator.\n\n"
                    "Recovery token for the exercise is stored below."
                ),
                (
                    "- Verify pager rotation\n"
                    "- Rotate the inbound mailbox\n"
                    f"- {current_app.config['FLAG_VALUE']}"
                ),
                0,
            ),
        )

    sample_user = db.execute("SELECT id FROM users WHERE username = ?", ("trainee",)).fetchone()
    if sample_user is None:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("trainee", generate_password_hash("handoff123"), "user"),
        )
        trainee_id = db.execute(
            "SELECT id FROM users WHERE username = ?",
            ("trainee",),
        ).fetchone()["id"]
        db.execute(
            """
            INSERT INTO packets (owner_id, title, body, checklist, is_public)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                trainee_id,
                "Template Usage Example",
                (
                    "Use [[include:ops-footer.txt]] to append the standard closing note.\n"
                    "The preview tool resolves snippet references before rendering."
                ),
                "- Mention blocked systems\n- Add on-call owner\n- Preview before publishing",
                1,
            ),
        )

    db.commit()
    db.close()
