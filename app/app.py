"""Acropolis Notes - a deliberately vulnerable Flask notes application.

This is the Phase 1 AppSec target for the Acropolis lab. It is a small but
complete, server-rendered notes product (register, log in, write Markdown notes,
tag and search them, import/export) that intentionally ships with a catalogue of
planted security flaws. Each flaw is marked inline with a ``VULN #n`` comment and
documented end to end in ``writeups/phase-1-appsec.md``.

Planted vulnerabilities (do NOT fix - they are the learning objective):
  #1 Hardcoded secrets (SECRET_KEY, ADMIN_API_KEY) live in source.
  #2 SQL injection in the login query (raw string concatenation).
  #3 IDOR on the view-note route (fetch by id, no ownership check).
  #4 Insecure deserialization in YAML import (yaml.Loader -> RCE).
  #5 Vulnerable dependency pinned in requirements.txt (requests==2.19.1).
  #6 Stored XSS: note titles/bodies render as raw, unsanitised HTML.
  Bonus: debug=True in production, passwords stored in plaintext.
"""

import re
from functools import wraps

import markdown
import yaml
from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from db import get_connection

# --- VULN #1: hardcoded secrets committed straight into source -------------
SECRET_KEY = "acropolis-dev-secret-key-2026-do-not-rotate"
ADMIN_API_KEY = "acro_live_sk_8f3b1c9d2e5a4f6b7c8d9e0f1a2b3c4d"

app = Flask(__name__)
app.secret_key = SECRET_KEY


# --------------------------------------------------------------------------- #
# Small data-access + view helpers
# --------------------------------------------------------------------------- #
def query_db(query, args=(), one=False):
    """Run a SELECT and return rows (or a single row when ``one`` is True)."""
    conn = get_connection()
    rows = conn.execute(query, args).fetchall()
    conn.close()
    if one:
        return rows[0] if rows else None
    return rows


def execute_db(query, args=()):
    """Run an INSERT/UPDATE/DELETE and return the last row id."""
    conn = get_connection()
    cur = conn.execute(query, args)
    conn.commit()
    last_id = cur.lastrowid
    conn.close()
    return last_id


def parse_tags(raw):
    """Split a comma-separated tag string into a clean, de-duplicated list."""
    out = []
    for part in (raw or "").split(","):
        tag = part.strip().lower()
        if tag and tag not in out:
            out.append(tag)
    return out


def normalize_tags(raw):
    """Normalise free-form tag input back into a stored comma-separated string."""
    return ", ".join(parse_tags(raw))


def user_tags(user_id):
    """Return the sorted, distinct tags used across one user's notes."""
    seen = []
    for row in query_db("SELECT tags FROM notes WHERE user_id = ?", (user_id,)):
        for tag in parse_tags(row["tags"]):
            if tag not in seen:
                seen.append(tag)
    return sorted(seen)


def excerpt(body, length=160):
    """Build a short plain-text preview of a note body for dashboard cards."""
    text = re.sub(r"[#>*_`>\-]+", " ", body or "")
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > length:
        text = text[:length].rstrip() + "..."
    return text


def render_markdown(text):
    """Render Markdown to HTML.

    VULN #6 (stored XSS): there is NO output sanitisation here. Raw HTML embedded
    in a note - including ``<script>`` - passes straight through, and the template
    emits the result with ``|safe``, so it executes when the note is viewed.
    """
    return markdown.markdown(text or "", extensions=["fenced_code", "tables", "nl2br"])


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.context_processor
def inject_sidebar():
    """Expose the signed-in user's name and tags to the app shell template."""
    if "user_id" not in session:
        return {}
    return {
        "nav_username": session.get("username"),
        "sidebar_tags": user_tags(session["user_id"]),
    }


# --------------------------------------------------------------------------- #
# Public + auth routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Choose a username and a password to continue.", "error")
            return render_template("register.html", username=username)
        try:
            # Passwords are stored in plaintext on purpose (bonus flaw).
            user_id = execute_db(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password),
            )
        except Exception:
            flash("That username is already taken.", "error")
            return render_template("register.html", username=username)
        session["user_id"] = user_id
        session["username"] = username
        flash("Account created - welcome to Acropolis Notes.", "success")
        return redirect(url_for("dashboard"))
    return render_template("register.html", username="")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # --- VULN #2: SQL injection ---------------------------------------- #
        # The login query is assembled by concatenating untrusted input directly
        # into the SQL string. A username of  ' OR '1'='1' --  bypasses auth.
        query = (
            "SELECT * FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        conn = get_connection()
        try:
            row = conn.execute(query).fetchone()
        except Exception:
            row = None
        conn.close()

        if row:
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            flash(f"Welcome back, {row['username']}.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
        return render_template("login.html", username=username)
    return render_template("login.html", username="")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


# --------------------------------------------------------------------------- #
# Dashboard + notes
# --------------------------------------------------------------------------- #
@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    active_tag = request.args.get("tag", "").strip().lower()

    rows = query_db(
        "SELECT * FROM notes WHERE user_id = ? ORDER BY datetime(updated_at) DESC",
        (user_id,),
    )
    total_notes = len(rows)
    all_tags = user_tags(user_id)

    cards = []
    for note in rows:
        tags = parse_tags(note["tags"])
        if active_tag and active_tag not in tags:
            continue
        cards.append(
            {
                "id": note["id"],
                "title": note["title"],
                "excerpt": excerpt(note["body"]),
                "tags": tags,
                "updated_at": note["updated_at"],
            }
        )

    return render_template(
        "dashboard.html",
        cards=cards,
        active_tag=active_tag,
        stats={"notes": total_notes, "tags": len(all_tags)},
    )


@app.route("/notes/new", methods=["GET", "POST"])
@login_required
def new_note():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "")
        tags = normalize_tags(request.form.get("tags", ""))
        if not title:
            flash("Give your note a title.", "error")
            return render_template(
                "note_form.html",
                mode="new",
                note={"title": title, "body": body, "tags": tags},
            )
        note_id = execute_db(
            "INSERT INTO notes (user_id, title, body, tags) VALUES (?, ?, ?, ?)",
            (session["user_id"], title, body, tags),
        )
        flash("Note created.", "success")
        return redirect(url_for("view_note", note_id=note_id))
    return render_template(
        "note_form.html", mode="new", note={"title": "", "body": "", "tags": ""}
    )


@app.route("/notes/<int:note_id>")
@login_required
def view_note(note_id):
    # --- VULN #3: IDOR ------------------------------------------------------ #
    # The note is fetched by id ALONE, with no check that it belongs to the
    # signed-in user. Any authenticated user can read any note - including the
    # admin's note holding the flag - simply by changing the id in the URL.
    note = query_db("SELECT * FROM notes WHERE id = ?", (note_id,), one=True)
    if note is None:
        abort(404)

    owner = query_db(
        "SELECT username FROM users WHERE id = ?", (note["user_id"],), one=True
    )
    # VULN #6: body rendered to HTML with no sanitisation, emitted via |safe.
    body_html = render_markdown(note["body"])

    return render_template(
        "note_view.html",
        note=note,
        body_html=body_html,
        tags=parse_tags(note["tags"]),
        owner=owner["username"] if owner else "unknown",
        is_owner=(note["user_id"] == session["user_id"]),
    )


@app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def edit_note(note_id):
    note = query_db("SELECT * FROM notes WHERE id = ?", (note_id,), one=True)
    if note is None:
        abort(404)
    # Editing IS ownership-checked; only the read path (above) is the IDOR sink.
    if note["user_id"] != session["user_id"]:
        abort(403)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "")
        tags = normalize_tags(request.form.get("tags", ""))
        if not title:
            flash("Give your note a title.", "error")
            return render_template(
                "note_form.html",
                mode="edit",
                note={"id": note_id, "title": title, "body": body, "tags": tags},
            )
        execute_db(
            "UPDATE notes SET title = ?, body = ?, tags = ?, "
            "updated_at = datetime('now') WHERE id = ?",
            (title, body, tags, note_id),
        )
        flash("Note updated.", "success")
        return redirect(url_for("view_note", note_id=note_id))

    return render_template("note_form.html", mode="edit", note=note)


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def delete_note(note_id):
    note = query_db("SELECT * FROM notes WHERE id = ?", (note_id,), one=True)
    if note is None:
        abort(404)
    if note["user_id"] != session["user_id"]:
        abort(403)
    execute_db("DELETE FROM notes WHERE id = ?", (note_id,))
    flash("Note deleted.", "success")
    return redirect(url_for("dashboard"))


# --------------------------------------------------------------------------- #
# Settings: profile, YAML import/export
# --------------------------------------------------------------------------- #
@app.route("/settings")
@login_required
def settings():
    # VULN #1 surfaced in the UI: the hardcoded ADMIN_API_KEY is shown verbatim
    # to any authenticated user.
    return render_template("settings.html", api_key=ADMIN_API_KEY)


@app.route("/settings/import", methods=["POST"])
@login_required
def import_notes():
    raw = request.form.get("yaml_data", "")
    uploaded = request.files.get("yaml_file")
    if uploaded and uploaded.filename:
        raw = uploaded.read().decode("utf-8", errors="replace")

    if not raw.strip():
        flash("Paste some YAML or choose a file to import.", "error")
        return redirect(url_for("settings"))

    try:
        # --- VULN #4: insecure deserialization ----------------------------- #
        # yaml.Loader is the full, unsafe loader. YAML tags such as
        #   !!python/object/apply:os.system ["id"]
        # are constructed during parsing, giving arbitrary code execution.
        data = yaml.load(raw, Loader=yaml.Loader)
    except yaml.YAMLError as exc:
        flash(f"Could not parse that YAML: {exc}", "error")
        return redirect(url_for("settings"))

    imported = 0
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("title"):
                tags_value = item.get("tags", "")
                if isinstance(tags_value, list):
                    tags_value = ", ".join(str(t) for t in tags_value)
                execute_db(
                    "INSERT INTO notes (user_id, title, body, tags) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        session["user_id"],
                        str(item.get("title")),
                        str(item.get("body", "")),
                        normalize_tags(str(tags_value)),
                    ),
                )
                imported += 1

    if imported:
        flash(f"Imported {imported} note(s).", "success")
    else:
        flash("No importable notes were found in that YAML.", "error")
    return redirect(url_for("settings"))


@app.route("/settings/export")
@login_required
def export_notes():
    rows = query_db(
        "SELECT title, body, tags, created_at FROM notes WHERE user_id = ? "
        "ORDER BY id",
        (session["user_id"],),
    )
    payload = [
        {
            "title": r["title"],
            "body": r["body"],
            "tags": r["tags"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]
    text = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    return Response(
        text,
        mimetype="application/x-yaml",
        headers={"Content-Disposition": "attachment; filename=acropolis-notes.yaml"},
    )


# --------------------------------------------------------------------------- #
# Friendly error pages
# --------------------------------------------------------------------------- #
@app.errorhandler(403)
@app.errorhandler(404)
def handle_http_error(error):
    return (
        render_template("error.html", code=error.code, message=error.description),
        error.code,
    )


if __name__ == "__main__":
    # Bonus flaw: debug=True exposes the interactive Werkzeug debugger / RCE
    # console and verbose tracebacks. Bound to all interfaces for the container.
    app.run(host="0.0.0.0", port=5000, debug=True)
