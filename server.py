#!/usr/bin/env python3
"""Log-to-CSV Converter — Flask backend with built-in log parsers."""

import csv
import io
import json
import os
import re
from datetime import datetime
from flask import Flask, request, jsonify, send_file, send_from_directory

app = Flask(__name__, static_folder="static", static_url_path="")

# ── Pre-compiled log parsers ────────────────────────────────────────────────

APACHE_REGEX = re.compile(
    r'^(\S+)\s+'          # IP
    r'(\S+)\s+'           # ident (RFC 1413)
    r'(\S+)\s+'           # userid
    r'\[([^\]]+)\]\s+'    # timestamp [day/month/year:hour:min:sec zone]
    r'"(\S+)\s+'          # HTTP method
    r'(\S+)\s+'           # URL / path
    r'(\S+)"\s+'          # protocol
    r'(\d{3})\s+'         # status code
    r'(\d+|-)\s*'         # size
    r'(?:"([^"]*)"\s*)?'  # referer (optional, combined format)
    r'(?:"([^"]*)")?$'    # user-agent (optional, combined format)
)

APACHE_COLUMNS = [
    "IP", "Ident", "UserID", "Data/Ora", "Metodo HTTP",
    "URL", "Protocollo", "Codice Stato", "Dimensione (byte)",
    "Referer", "User-Agent"
]

SYSLOG_REGEX = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # timestamp
    r'(\S+)\s+'                                      # hostname
    r'([\w./-]+?)'                                   # tag/process
    r'(?:\[(\d+)\])?'                                # optional PID
    r':\s*(.*)$',                                     # message
    re.DOTALL
)

SYSLOG_COLUMNS = [
    "Data/Ora", "Hostname", "Processo", "PID", "Messaggio"
]


def parse_apache(text: str) -> dict:
    """Parse Apache access log lines into structured records."""
    rows = []
    errors = []
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        m = APACHE_REGEX.match(line)
        if m:
            rows.append(list(m.groups()))
        else:
            errors.append({"line": i, "text": line[:120]})
    return {
        "columns": APACHE_COLUMNS,
        "rows": rows,
        "errors": errors,
        "total_parsed": len(rows),
        "total_errors": len(errors),
    }


def parse_syslog(text: str) -> dict:
    """Parse Syslog (RFC 3164) lines into structured records."""
    rows = []
    errors = []
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        m = SYSLOG_REGEX.match(line)
        if m:
            rows.append(list(m.groups()))
        else:
            errors.append({"line": i, "text": line[:120]})
    return {
        "columns": SYSLOG_COLUMNS,
        "rows": rows,
        "errors": errors,
        "total_parsed": len(rows),
        "total_errors": len(errors),
    }


def parse_custom(text: str, pattern: str) -> dict:
    """Parse log lines using a user-supplied regex.

    If the pattern contains named groups (?P<name>...), those names become
    column headers. Otherwise columns are labelled Col_1, Col_2, etc.
    """
    try:
        compiled = re.compile(pattern)
    except re.error as e:
        return {"error": f"Regex non valida: {e}"}

    # Detect named groups
    named = list(compiled.groupindex.keys())
    use_named = bool(named)
    if use_named:
        columns = sorted(named, key=lambda n: compiled.groupindex[n])
    else:
        columns = []

    rows = []
    errors = []
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        m = compiled.search(line)
        if m:
            if use_named:
                vals = [m.group(name) for name in columns]
            else:
                vals = list(m.groups())
                if not columns:
                    columns = [f"Col_{j+1}" for j in range(len(vals))]
            rows.append(vals)
        else:
            errors.append({"line": i, "text": line[:120]})

    return {
        "columns": columns,
        "rows": rows,
        "errors": errors,
        "total_parsed": len(rows),
        "total_errors": len(errors),
    }


def build_csv(columns: list, rows: list) -> str:
    """Convert parsed data to a CSV string."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(columns)
    writer.writerows(rows)
    return buf.getvalue()


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/robots.txt")
def robots():
    return send_from_directory(".", "robots.txt")


@app.route("/sitemap.xml")
def sitemap():
    return send_from_directory(".", "sitemap.xml")


@app.route("/api/parse", methods=["POST"])
def api_parse():
    """Parse an uploaded log file and return structured JSON."""
    if "file" not in request.files:
        return jsonify({"error": "Nessun file caricato"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Nome file vuoto"}), 400

    fmt = request.form.get("format", "apache")
    custom_regex = request.form.get("regex", "")

    try:
        text = file.read().decode("utf-8", errors="replace")
    except Exception as e:
        return jsonify({"error": f"Impossibile leggere il file: {e}"}), 400

    if not text.strip():
        return jsonify({"error": "Il file è vuoto"}), 400

    if fmt == "apache":
        result = parse_apache(text)
    elif fmt == "syslog":
        result = parse_syslog(text)
    elif fmt == "custom":
        if not custom_regex.strip():
            return jsonify({"error": "Inserisci un'espressione regolare per il formato personalizzato"}), 400
        result = parse_custom(text, custom_regex.strip())
    else:
        return jsonify({"error": f"Formato '{fmt}' non supportato"}), 400

    if "error" in result:
        return jsonify(result), 400

    return jsonify(result)


@app.route("/api/download", methods=["POST"])
def api_download():
    """Parse an uploaded log file and return it as a CSV download."""
    if "file" not in request.files:
        return jsonify({"error": "Nessun file caricato"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Nome file vuoto"}), 400

    fmt = request.form.get("format", "apache")
    custom_regex = request.form.get("regex", "")

    try:
        text = file.read().decode("utf-8", errors="replace")
    except Exception as e:
        return jsonify({"error": f"Impossibile leggere il file: {e}"}), 400

    if fmt == "apache":
        result = parse_apache(text)
    elif fmt == "syslog":
        result = parse_syslog(text)
    elif fmt == "custom":
        if not custom_regex.strip():
            return jsonify({"error": "Inserisci un'espressione regolare"}), 400
        result = parse_custom(text, custom_regex.strip())
    else:
        return jsonify({"error": f"Formato '{fmt}' non supportato"}), 400

    if "error" in result:
        return jsonify(result), 400

    csv_text = build_csv(result["columns"], result["rows"])
    buf = io.BytesIO()
    buf.write(csv_text.encode("utf-8-sig"))
    buf.seek(0)

    return send_file(
        buf,
        mimetype="text/csv",
        as_attachment=True,
        download_name="log_convertito.csv",
    )


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 4599))
    app.run(host="0.0.0.0", port=port, debug=False)
