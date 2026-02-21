"""
ConvertFin — Conversor de Extratos Bancários PDF
Versão 1.0
"""

import os, sqlite3, re, io, hashlib, secrets, uuid
from datetime import datetime, date
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, send_file, jsonify, g)
import pdfplumber
import pandas as pd

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB_PATH = os.path.join(os.path.dirname(__file__), "convertfin.db")

FREE_LIMIT     = 5          # conversões gratuitas por mês
PRO_PRICE      = "29,99"
APP_NAME       = "ConvertFin"

# ──────────────────────────────────────────────
# DATABASE
# ──────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT    NOT NULL,
            email         TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL,
            plan          TEXT    NOT NULL DEFAULT 'free',
            monthly_used  INTEGER NOT NULL DEFAULT 0,
            reset_month   TEXT    NOT NULL DEFAULT '',
            extra_credits INTEGER NOT NULL DEFAULT 0,
            is_admin      INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS conversions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            filename   TEXT,
            bank       TEXT,
            format     TEXT,
            rows       INTEGER DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        );
        INSERT OR IGNORE INTO settings(key, value) VALUES ('ai_enabled', '0');
        INSERT OR IGNORE INTO settings(key, value) VALUES ('maintenance', '0');
    """)
    db.commit()
    db.close()

def get_setting(key):
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else ""

def set_setting(key, value):
    get_db().execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, value))
    get_db().commit()

# ──────────────────────────────────────────────
# AUTH HELPERS
# ──────────────────────────────────────────────
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Faça login para continuar.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user or not user["is_admin"]:
            flash("Acesso restrito.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper

def reset_if_new_month(user):
    """Reseta contador de conversões se for novo mês."""
    current_month = date.today().strftime("%Y-%m")
    if user["reset_month"] != current_month:
        get_db().execute(
            "UPDATE users SET monthly_used=0, reset_month=? WHERE id=?",
            (current_month, user["id"])
        )
        get_db().commit()
        return get_db().execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    return user

def can_convert(user):
    """Verifica se o usuário pode fazer mais conversões."""
    user = reset_if_new_month(user)
    if user["plan"] == "pro":
        return True, user
    total_allowed = FREE_LIMIT + user["extra_credits"]
    return user["monthly_used"] < total_allowed, user

def remaining_conversions(user):
    user = reset_if_new_month(user)
    if user["plan"] == "pro":
        return None  # ilimitado
    return max(0, FREE_LIMIT + user["extra_credits"] - user["monthly_used"])

# ──────────────────────────────────────────────
# PDF PARSERS
# ──────────────────────────────────────────────
def detect_bank(text):
    t = text.lower()
    banks = {
        "nubank":    ["nubank", "nu pagamentos"],
        "itau":      ["itaú", "itau unibanco"],
        "bradesco":  ["bradesco"],
        "inter":     ["banco inter", "bco. inter"],
        "santander": ["santander"],
        "caixa":     ["caixa econômica", "cef"],
        "bb":        ["banco do brasil", "bb s.a"],
        "sicoob":    ["sicoob"],
        "sicredi":   ["sicredi"],
        "btg":       ["btg pactual"],
        "c6":        ["c6 bank"],
        "picpay":    ["picpay"],
        "pagbank":   ["pagbank", "pagseguro"],
    }
    for bank, keywords in banks.items():
        if any(k in t for k in keywords):
            return bank
    return "generico"

def parse_text_to_rows(text, bank):
    """Extrai transações do texto bruto."""
    rows = []
    lines = text.split("\n")

    patterns = [
        re.compile(r"(\d{2}/\d{2}/\d{4})\s+(.+?)\s+([-]?\d{1,3}(?:\.\d{3})*,\d{2})\s*$"),
        re.compile(r"(\d{2}/\d{2}/\d{4})\s+(.+?)\s+([-]?R?\$?\s*\d{1,3}(?:[.,]\d{3})*[.,]\d{2})"),
        re.compile(r"(\d{2}/\d{2})\s+(.+?)\s+([-]?\d{1,3}(?:\.\d{3})*,\d{2})\s*$"),
    ]

    for line in lines:
        line = line.strip()
        if not line:
            continue
        for pat in patterns:
            m = pat.search(line)
            if m:
                date_str, desc, val = m.group(1), m.group(2), m.group(3)
                val = val.replace("R$", "").replace(" ", "").strip()
                if "," in val and "." in val:
                    val_f = float(val.replace(".", "").replace(",", "."))
                elif "," in val:
                    val_f = float(val.replace(",", "."))
                else:
                    try:
                        val_f = float(val)
                    except:
                        continue
                # Normaliza data para dd/mm/aaaa
                if len(date_str) == 5:
                    date_str = date_str + "/" + str(datetime.now().year)
                rows.append({
                    "data":      date_str,
                    "descricao": desc.strip()[:80],
                    "valor":     val_f,
                    "banco":     bank.upper(),
                })
                break
    return rows

def parse_tables_to_rows(tables, bank):
    rows = []
    date_pat  = re.compile(r"\d{2}[/\-]\d{2}[/\-]?\d{0,4}")
    value_pat = re.compile(r"[-]?\d{1,3}(?:[.,]\d{3})*[.,]\d{2}$")

    for table in tables:
        for row in table:
            if not row:
                continue
            cells = [str(c).strip() if c else "" for c in row]
            date_cell = next((c for c in cells if date_pat.fullmatch(c)), None)
            if not date_cell:
                continue
            val_cells = [c for c in cells if value_pat.fullmatch(c.replace(" ", ""))]
            if not val_cells:
                continue
            val_raw = val_cells[-1].replace(" ", "")
            if "," in val_raw and "." in val_raw:
                val_f = float(val_raw.replace(".", "").replace(",", "."))
            elif "," in val_raw:
                val_f = float(val_raw.replace(",", "."))
            else:
                try:
                    val_f = float(val_raw)
                except:
                    continue
            desc_parts = [c for c in cells if c and c != date_cell and c not in val_cells]
            desc = " ".join(desc_parts).strip()[:80] or "Sem descrição"
            rows.append({"data": date_cell, "descricao": desc, "valor": val_f, "banco": bank.upper()})
    return rows

def convert_pdf(file_bytes):
    """Pipeline principal de conversão."""
    full_text, all_tables = "", []
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        for page in pdf.pages:
            t = page.extract_text() or ""
            full_text += t + "\n"
            tables = page.extract_tables()
            if tables:
                all_tables.extend(tables)

    bank = detect_bank(full_text)
    rows = parse_tables_to_rows(all_tables, bank) if all_tables else []
    if not rows:
        rows = parse_text_to_rows(full_text, bank)

    # Ordenar por data
    def parse_date(r):
        try:
            return datetime.strptime(r["data"], "%d/%m/%Y")
        except:
            return datetime.min

    rows.sort(key=parse_date)
    return rows, bank

# ──────────────────────────────────────────────
# OFX GENERATOR
# ──────────────────────────────────────────────
def generate_ofx(rows, bank):
    now_str = datetime.now().strftime("%Y%m%d%H%M%S")
    if rows:
        try:
            dt_start = datetime.strptime(rows[0]["data"], "%d/%m/%Y").strftime("%Y%m%d")
            dt_end   = datetime.strptime(rows[-1]["data"], "%d/%m/%Y").strftime("%Y%m%d")
        except:
            dt_start = dt_end = datetime.now().strftime("%Y%m%d")
    else:
        dt_start = dt_end = datetime.now().strftime("%Y%m%d")

    total = sum(r["valor"] for r in rows)

    transactions = ""
    for i, r in enumerate(rows, 1):
        try:
            dt = datetime.strptime(r["data"], "%d/%m/%Y").strftime("%Y%m%d")
        except:
            dt = datetime.now().strftime("%Y%m%d")
        ttype  = "CREDIT" if r["valor"] >= 0 else "DEBIT"
        amount = f"{r['valor']:.2f}".replace(",", ".")
        memo   = r["descricao"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        transactions += f"""
        <STMTTRN>
          <TRNTYPE>{ttype}</TRNTYPE>
          <DTPOSTED>{dt}120000[-3:BRT]</DTPOSTED>
          <TRNAMT>{amount}</TRNAMT>
          <FITID>CF{now_str}{i:06d}</FITID>
          <MEMO>{memo}</MEMO>
        </STMTTRN>"""

    ofx = f"""OFXHEADER:100
DATA:OFXSGML
VERSION:102
SECURITY:NONE
ENCODING:UTF-8
CHARSET:1252
COMPRESSION:NONE
OLDFILEUID:NONE
NEWFILEUID:NONE

<OFX>
  <SIGNONMSGSRSV1>
    <SONRS>
      <STATUS><CODE>0</CODE><SEVERITY>INFO</SEVERITY></STATUS>
      <DTSERVER>{now_str}[-3:BRT]</DTSERVER>
      <LANGUAGE>POR</LANGUAGE>
    </SONRS>
  </SIGNONMSGSRSV1>
  <BANKMSGSRSV1>
    <STMTTRNRS>
      <TRNUID>1001</TRNUID>
      <STATUS><CODE>0</CODE><SEVERITY>INFO</SEVERITY></STATUS>
      <STMTRS>
        <CURDEF>BRL</CURDEF>
        <BANKACCTFROM>
          <BANKID>000</BANKID>
          <ACCTID>CF-{bank.upper()}-001</ACCTID>
          <ACCTTYPE>CHECKING</ACCTTYPE>
        </BANKACCTFROM>
        <BANKTRANLIST>
          <DTSTART>{dt_start}</DTSTART>
          <DTEND>{dt_end}</DTEND>{transactions}
        </BANKTRANLIST>
        <LEDGERBAL>
          <BALAMT>{total:.2f}</BALAMT>
          <DTASOF>{now_str}[-3:BRT]</DTASOF>
        </LEDGERBAL>
      </STMTRS>
    </STMTTRNRS>
  </BANKMSGSRSV1>
</OFX>"""
    return ofx

# ──────────────────────────────────────────────
# ROUTES — AUTH
# ──────────────────────────────────────────────
@app.route("/")
def index():
    user = get_current_user()
    return render_template("index.html", user=user, app_name=APP_NAME, pro_price=PRO_PRICE)

@app.route("/register", methods=["GET","POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name     = request.form.get("name","").strip()
        email    = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        confirm  = request.form.get("confirm","")
        if not all([name, email, password]):
            flash("Preencha todos os campos.", "danger")
        elif password != confirm:
            flash("As senhas não coincidem.", "danger")
        elif len(password) < 6:
            flash("A senha deve ter ao menos 6 caracteres.", "danger")
        else:
            db = get_db()
            if db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
                flash("E-mail já cadastrado.", "danger")
            else:
                db.execute(
                    "INSERT INTO users(name,email,password_hash,reset_month) VALUES(?,?,?,?)",
                    (name, email, hash_password(password), date.today().strftime("%Y-%m"))
                )
                db.commit()
                user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                session["user_id"] = user["id"]
                flash(f"Bem-vindo(a), {name}!", "success")
                return redirect(url_for("dashboard"))
    return render_template("register.html", app_name=APP_NAME)

@app.route("/login", methods=["GET","POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email    = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and user["password_hash"] == hash_password(password):
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        flash("E-mail ou senha incorretos.", "danger")
    return render_template("login.html", app_name=APP_NAME)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ──────────────────────────────────────────────
# ROUTES — DASHBOARD / CONVERTER
# ──────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    user = reset_if_new_month(user)
    rem  = remaining_conversions(user)
    history = get_db().execute(
        "SELECT * FROM conversions WHERE user_id=? ORDER BY created_at DESC LIMIT 20",
        (user["id"],)
    ).fetchall()
    ai_enabled = get_setting("ai_enabled") == "1"
    return render_template("dashboard.html",
        user=user, rem=rem, history=history,
        free_limit=FREE_LIMIT, pro_price=PRO_PRICE,
        app_name=APP_NAME, ai_enabled=ai_enabled)

@app.route("/api/convert", methods=["POST"])
@login_required
def api_convert():
    user = get_current_user()
    allowed, user = can_convert(user)

    if not allowed:
        return jsonify({"error": "limite", "message": "Limite de conversões atingido."}), 403

    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado."}), 400

    f = request.files["file"]
    if not f.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Apenas arquivos PDF são aceitos."}), 400

    output_fmt = request.form.get("format", "ofx").lower()
    file_bytes = f.read()

    if len(file_bytes) > 15 * 1024 * 1024:
        return jsonify({"error": "Arquivo muito grande. Máximo: 15 MB."}), 400

    try:
        rows, bank = convert_pdf(file_bytes)
    except Exception as e:
        return jsonify({"error": f"Erro ao processar PDF: {str(e)}"}), 500

    if not rows:
        return jsonify({"error": (
            "Não foi possível identificar transações neste arquivo. "
            "Verifique se o PDF é pesquisável (não é uma imagem escaneada) "
            "e tente novamente. Caso o problema persista, entre em contato com o suporte."
        )}), 422

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Gera arquivo de saída
    if output_fmt == "ofx":
        content  = generate_ofx(rows, bank).encode("utf-8")
        mimetype = "application/x-ofx"
        filename = f"extrato_{bank}_{ts}.ofx"
    elif output_fmt == "excel":
        df = pd.DataFrame(rows).rename(columns={"data":"Data","descricao":"Descrição","valor":"Valor (R$)","banco":"Banco"})
        total_row = pd.DataFrame([{"Data":"TOTAL","Descrição":"","Valor (R$)":round(df["Valor (R$)"].sum(),2),"Banco":""}])
        df = pd.concat([df, total_row], ignore_index=True)
        buf = io.BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Extrato")
        buf.seek(0)
        content  = buf.read()
        mimetype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        filename = f"extrato_{bank}_{ts}.xlsx"
    else:  # csv
        df = pd.DataFrame(rows).rename(columns={"data":"Data","descricao":"Descrição","valor":"Valor (R$)","banco":"Banco"})
        total_row = pd.DataFrame([{"Data":"TOTAL","Descrição":"","Valor (R$)":round(df["Valor (R$)"].sum(),2),"Banco":""}])
        df = pd.concat([df, total_row], ignore_index=True)
        content  = df.to_csv(index=False, sep=";", decimal=",", encoding="utf-8-sig").encode("utf-8-sig")
        mimetype = "text/csv"
        filename = f"extrato_{bank}_{ts}.csv"

    # Registra uso
    db = get_db()
    db.execute("UPDATE users SET monthly_used = monthly_used + 1 WHERE id=?", (user["id"],))
    db.execute(
        "INSERT INTO conversions(user_id,filename,bank,format,rows) VALUES(?,?,?,?,?)",
        (user["id"], f.filename, bank.upper(), output_fmt.upper(), len(rows))
    )
    db.commit()

    return send_file(
        io.BytesIO(content),
        mimetype=mimetype,
        as_attachment=True,
        download_name=filename
    )

@app.route("/api/usage")
@login_required
def api_usage():
    user = get_current_user()
    user = reset_if_new_month(user)
    rem  = remaining_conversions(user)
    return jsonify({
        "plan": user["plan"],
        "used": user["monthly_used"],
        "limit": FREE_LIMIT + user["extra_credits"] if user["plan"] == "free" else None,
        "remaining": rem
    })

# ──────────────────────────────────────────────
# ROUTES — PLANOS
# ──────────────────────────────────────────────
@app.route("/planos")
def planos():
    user = get_current_user()
    return render_template("planos.html", user=user, app_name=APP_NAME, pro_price=PRO_PRICE)

@app.route("/assinar")
@login_required
def assinar():
    # Placeholder — integrar Stripe/Hotmart aqui
    flash("Redirecionando para o pagamento...", "info")
    return render_template("assinar.html", user=get_current_user(), app_name=APP_NAME, pro_price=PRO_PRICE)

@app.route("/webhook/pagamento", methods=["POST"])
def webhook_pagamento():
    """
    Webhook de confirmação de pagamento.
    Configure este endpoint no Stripe ou Hotmart.
    Quando receber confirmação, atualiza o plano do usuário para 'pro'.
    """
    data  = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    token = data.get("token", "")

    # Valide o token do seu provedor de pagamento aqui
    WEBHOOK_TOKEN = os.environ.get("WEBHOOK_TOKEN", "mude-isso-em-producao")
    if token != WEBHOOK_TOKEN:
        return jsonify({"error": "Não autorizado"}), 403

    if email:
        db = get_db()
        db.execute("UPDATE users SET plan='pro' WHERE email=?", (email,))
        db.commit()
        return jsonify({"ok": True})
    return jsonify({"error": "E-mail não fornecido"}), 400

# ──────────────────────────────────────────────
# ROUTES — ADMIN
# ──────────────────────────────────────────────
@app.route("/admin")
@login_required
@admin_required
def admin():
    db   = get_db()
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    total_conversions = db.execute("SELECT COUNT(*) as c FROM conversions").fetchone()["c"]
    pro_users = db.execute("SELECT COUNT(*) as c FROM users WHERE plan='pro'").fetchone()["c"]
    free_users = db.execute("SELECT COUNT(*) as c FROM users WHERE plan='free'").fetchone()["c"]
    ai_enabled = get_setting("ai_enabled") == "1"
    maintenance = get_setting("maintenance") == "1"
    recent = db.execute("""
        SELECT c.*, u.name, u.email FROM conversions c
        JOIN users u ON u.id = c.user_id
        ORDER BY c.created_at DESC LIMIT 30
    """).fetchall()
    return render_template("admin.html",
        users=users, total_conversions=total_conversions,
        pro_users=pro_users, free_users=free_users,
        ai_enabled=ai_enabled, maintenance=maintenance,
        recent=recent, app_name=APP_NAME
    )

@app.route("/admin/user/<int:uid>", methods=["POST"])
@login_required
@admin_required
def admin_user_action(uid):
    action = request.form.get("action")
    db = get_db()
    if action == "set_pro":
        db.execute("UPDATE users SET plan='pro' WHERE id=?", (uid,))
    elif action == "set_free":
        db.execute("UPDATE users SET plan='free' WHERE id=?", (uid,))
    elif action == "add_credits":
        credits = int(request.form.get("credits", 0))
        db.execute("UPDATE users SET extra_credits = extra_credits + ? WHERE id=?", (credits, uid))
    elif action == "reset_usage":
        db.execute("UPDATE users SET monthly_used=0 WHERE id=?", (uid,))
    elif action == "set_admin":
        db.execute("UPDATE users SET is_admin=1 WHERE id=?", (uid,))
    elif action == "remove_admin":
        db.execute("UPDATE users SET is_admin=0 WHERE id=?", (uid,))
    elif action == "delete":
        db.execute("DELETE FROM conversions WHERE user_id=?", (uid,))
        db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    flash("Ação realizada com sucesso.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/settings", methods=["POST"])
@login_required
@admin_required
def admin_settings():
    ai  = "1" if request.form.get("ai_enabled") == "on" else "0"
    mnt = "1" if request.form.get("maintenance") == "on" else "0"
    set_setting("ai_enabled", ai)
    set_setting("maintenance", mnt)
    flash("Configurações salvas.", "success")
    return redirect(url_for("admin"))

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", app_name=APP_NAME), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html", app_name=APP_NAME), 500

# ──────────────────────────────────────────────
# MAINTENANCE CHECK
# ──────────────────────────────────────────────
@app.before_request
def check_maintenance():
    allowed = ["static", "login", "admin", "admin_user_action", "admin_settings"]
    if request.endpoint in allowed:
        return
    if get_setting("maintenance") == "1":
        user = get_current_user()
        if not user or not user["is_admin"]:
            return render_template("manutencao.html", app_name=APP_NAME), 503

# ──────────────────────────────────────────────
# TEMPLATE FILTER
# ──────────────────────────────────────────────
@app.context_processor
def inject_globals():
    return {"now": datetime.now(), "get_current_user": get_current_user}

@app.template_filter("brl")
def brl_filter(value):
    try:
        return f"R$ {float(value):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    except:
        return value

# ──────────────────────────────────────────────
# INIT + RUN
# ──────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    # Cria admin padrão se não existir
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    if not db.execute("SELECT id FROM users WHERE is_admin=1").fetchone():
        db.execute("""
            INSERT OR IGNORE INTO users(name,email,password_hash,plan,is_admin,reset_month)
            VALUES(?,?,?,?,?,?)
        """, ("Admin", "admin@convertfin.com.br",
              hashlib.sha256(b"admin123").hexdigest(),
              "pro", 1, date.today().strftime("%Y-%m")))
        db.commit()
        print("Admin criado: admin@convertfin.com.br / admin123")
    db.close()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
