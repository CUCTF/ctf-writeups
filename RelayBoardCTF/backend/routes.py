from html import escape

from flask import Blueprint, abort, redirect, render_template, request, session, url_for

from .auth import admin_required, login_required
from .db import get_db
from .preview import render_handoff_preview


main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    packets = get_db().execute(
        """
        SELECT packets.id, packets.title, packets.body, packets.checklist, packets.is_public, users.username
        FROM packets
        JOIN users ON users.id = packets.owner_id
        WHERE packets.is_public = 1
           OR packets.owner_id = ?
           OR ? = 'admin'
        ORDER BY packets.id DESC
        """,
        (
            session.get("user_id", -1),
            session.get("role", ""),
        ),
    ).fetchall()
    return render_template("index.html", packets=packets)


@main_bp.route("/compose", methods=["GET", "POST"])
@login_required
def compose():
    error = None
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        checklist = request.form.get("checklist", "").strip()
        is_public = 1 if request.form.get("is_public") == "on" else 0

        if not title or not body or not checklist:
            error = "Every packet needs a title, body, and checklist."
        else:
            get_db().execute(
                """
                INSERT INTO packets (owner_id, title, body, checklist, is_public)
                VALUES (?, ?, ?, ?, ?)
                """,
                (session["user_id"], title, body, checklist, is_public),
            )
            get_db().commit()
            return redirect(url_for("main.index"))
    return render_template("compose.html", error=error)


@main_bp.route("/preview", methods=["POST"])
@login_required
def preview():
    title = request.form.get("title", "")
    body = request.form.get("body", "")
    checklist = request.form.get("checklist", "")

    rendered = {
        "title": escape(render_handoff_preview(title)),
        "body": escape(render_handoff_preview(body)),
        "checklist": escape(render_handoff_preview(checklist)),
    }
    return render_template("preview.html", rendered=rendered)


@main_bp.route("/packets/<int:packet_id>")
def packet_detail(packet_id):
    packet = get_db().execute(
        """
        SELECT packets.*, users.username
        FROM packets
        JOIN users ON users.id = packets.owner_id
        WHERE packets.id = ?
        """,
        (packet_id,),
    ).fetchone()

    if packet is None:
        abort(404)

    if (
        packet["is_public"] != 1
        and session.get("role") != "admin"
        and session.get("user_id") != packet["owner_id"]
    ):
        abort(403)

    return render_template("packet_detail.html", packet=packet)


@main_bp.route("/admin/archive/<int:packet_id>")
@admin_required
def admin_archive(packet_id):
    packet = get_db().execute(
        """
        SELECT packets.*, users.username
        FROM packets
        JOIN users ON users.id = packets.owner_id
        WHERE packets.id = ?
        """,
        (packet_id,),
    ).fetchone()
    if packet is None:
        abort(404)
    return render_template("packet_detail.html", packet=packet)
