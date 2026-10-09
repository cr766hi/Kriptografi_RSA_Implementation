"""Educational EHR demo (versi RBAC): manual RSA, CLI, dan web localhost dengan login 3 role."""

from __future__ import annotations

import argparse
from datetime import datetime
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from random import SystemRandom
from urllib.parse import parse_qs


_RNG = SystemRandom()

# False: web menyembunyikan p, q, phi, d, dan langkah bit dekripsi (menjaga separation of duties).
# True : web menampilkan semua tahap RSA. Pakai hanya untuk screenshot/demo.
SHOW_SECRETS = False


# ----------------------------------------------------------------------------
# Auth manual (tanpa hashlib/secrets). Hanya dipakai oleh versi web.
# ----------------------------------------------------------------------------

PERMISSIONS = {
    "admin": {"keys", "view_raw", "audit"},
    "dokter": {"insert", "view_raw", "decrypt"},
    "staf": {"insert", "view_raw"},
}

ROLE_INFO = {
    "admin": "Mengelola kunci RSA dan memantau riwayat aktivitas. Tidak dapat membuka diagnosis pasien.",
    "dokter": "Mencatat data pasien dan membuka diagnosis dengan kunci privat.",
    "staf": "Mencatat data pasien menggunakan kunci publik. Tidak dapat membuka diagnosis.",
}

USERS: dict[str, dict] = {}
SESSIONS: dict[str, str] = {}  # token -> username


def toy_hash(password: str, salt: str) -> int:
    """Hash buatan sendiri (djb2 berulang). BUKAN hash kriptografis, hanya demo."""
    h = 5381
    for _ in range(1000):
        for ch in salt + password:
            h = (h * 33 + ord(ch)) % (1 << 64)
    return h


def add_user(username: str, password: str, role: str) -> None:
    salt = format(_RNG.getrandbits(64), "016x")
    USERS[username] = {"salt": salt, "hash": toy_hash(password, salt), "role": role}


def verify_user(username: str, password: str) -> str | None:
    user = USERS.get(username)
    if user is None or toy_hash(password, user["salt"]) != user["hash"]:
        return None
    return user["role"]


def new_session_token() -> str:
    return format(_RNG.getrandbits(128), "032x")


def parse_cookie(header: str) -> dict[str, str]:
    result = {}
    for part in header.split(";"):
        if "=" in part:
            key, _, value = part.strip().partition("=")
            result[key] = value
    return result


# ----------------------------------------------------------------------------
# RSA manual
# ----------------------------------------------------------------------------

def gcd(a: int, b: int) -> int:
    """Return the greatest common divisor using Euclid's algorithm."""
    while b:
        a, b = b, a % b
    return abs(a)


def is_prime(n: int) -> bool:
    """Check primality by trial division (suitable for this small demo)."""
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    divisor = 3
    while divisor * divisor <= n:
        if n % divisor == 0:
            return False
        divisor += 2
    return True


def generate_prime(min_val: int = 257, max_val: int = 997) -> int:
    """Choose a prime from an inclusive range."""
    if min_val > max_val:
        raise ValueError("Batas minimum harus <= batas maksimum.")
    candidates = [n for n in range(min_val, max_val + 1) if is_prime(n)]
    if not candidates:
        raise ValueError("Rentang tidak memuat bilangan prima.")
    return _RNG.choice(candidates)


def mod_inverse(e: int, phi: int) -> int:
    """Find e⁻¹ mod phi with the extended Euclidean algorithm."""
    if phi <= 1:
        raise ValueError("phi harus lebih besar dari satu.")
    old_r, r, old_s, s = e, phi, 1, 0
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    if old_r != 1:
        raise ValueError("Invers modular tidak tersedia.")
    return old_s % phi


def generate_keys() -> tuple[tuple[int, int], tuple[int, int], dict[str, int]]:
    """Generate public/private keys and return the values for teaching logs."""
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = _RNG.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = _RNG.randrange(2, phi)
    d = mod_inverse(e, phi)
    return (e, n), (d, n), {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d}


def extended_euclid_log(a: int, b: int) -> list[str]:
    rows, old_r, r, old_s, s, old_t, t = [], a, b, 1, 0, 0, 1
    while r:
        q = old_r // r
        rows.append(f"{old_r} = {q} × {r} + {old_r % r}")
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    rows.append(f"{old_r} = {old_s} × {a} + ({old_t}) × {b}")
    return rows


def key_generation_log(detail: dict[str, int]) -> str:
    """Log lengkap (berisi d). Dicetak di terminal."""
    p, q, n = detail["p"], detail["q"], detail["n"]
    phi, e, d = detail["phi"], detail["e"], detail["d"]
    return "\n".join((
        "=== RSA KEY GENERATION ===", "", f"p = {p}", f"q = {q}", "",
        f"n = p × q = {p} × {q} = {n}",
        f"phi(n) = (p-1)(q-1) = {p-1} × {q-1} = {phi}", "",
        "Extended Euclidean Algorithm untuk e dan phi(n):", *extended_euclid_log(e, phi), "",
        f"gcd({e}, {phi}) = 1", f"d = e⁻¹ mod phi(n) = {d}",
        f"Public Key  = ({e}, {n})", f"Private Key = ({d}, {n})",
    ))


def mod_pow(base: int, exp: int, mod: int, log: list[str] | None = None) -> int: #perhitungan perpangkatan modulo seacara manual/RSA
    """Square-and-multiply modular exponentiation, implemented iteratively."""
    if mod <= 0 or exp < 0:
        raise ValueError("Modulus harus positif dan eksponen tidak boleh negatif.")
    result, factor, step = 1, base % mod, 0
    while exp:
        bit = exp & 1
        if log is not None:
            log.append(f"Langkah {step + 1}: bit={bit}, hasil={result}, basis={factor}")
        if bit:
            result = result * factor % mod
        factor = factor * factor % mod
        exp >>= 1
        step += 1
    return result


def text_to_ascii(text: str) -> list[int]:
    """Convert characters to ASCII code points; reject non-ASCII input."""
    values = [ord(char) for char in text]
    if any(value > 127 for value in values):
        raise ValueError("Diagnosis harus berisi karakter ASCII (0–127).")
    return values


def encrypt_field(plaintext: str, public_key: tuple[int, int], log: list[str] | None = None) -> str:
    e, n = public_key
    values = text_to_ascii(plaintext)
    if n <= 127:
        raise ValueError("Modulus n harus lebih besar dari 127.")
    output = []
    if log is not None:
        log.extend(["=== TEXT TO ASCII ===", *(f"{char} -> {value}" for char, value in zip(plaintext, values)), "", "=== RSA ENCRYPTION ==="])
    for char, value in zip(plaintext, values):
        steps: list[str] = []
        cipher = mod_pow(value, e, n, steps)
        output.append(str(cipher))
        if log is not None:
            log.extend([f"\nCharacter : {char}", f"ASCII     : {value}", "c = m^e mod n", f"c = {value}^{e} mod {n}", *steps, f"c = {cipher}"])
    return " ".join(output)


def _parse_ciphertext(ciphertext_str: str, n: int) -> list[int]:
    parts = ciphertext_str.split()
    if not parts:
        raise ValueError("Ciphertext tidak boleh kosong.")
    if any(not part.isdecimal() for part in parts):
        raise ValueError("Ciphertext harus berupa angka yang dipisahkan spasi.")
    values = [int(part) for part in parts]
    if any(value < 0 or value >= n for value in values):
        raise ValueError("Nilai ciphertext harus berada pada rentang 0 sampai n-1.")
    return values


def decrypt_field(ciphertext_str: str, private_key: tuple[int, int], log: list[str] | None = None) -> str:
    d, n = private_key
    values = _parse_ciphertext(ciphertext_str, n)
    chars = []
    if log is not None:
        log.append("=== RSA DECRYPTION ===")
    for cipher in values:
        steps: list[str] = []
        value = mod_pow(cipher, d, n, steps)
        if value > 127:
            raise ValueError("Hasil dekripsi bukan karakter ASCII yang valid.")
        char = chr(value)
        chars.append(char)
        if log is not None:
            log.extend([f"\nCiphertext = {cipher}", "m = c^d mod n", f"m = {cipher}^{d} mod {n}", *steps, f"m = {value}", f"ASCII {value} = {char}"])
    return "".join(chars)


def encrypt_rows(plaintext: str, public_key: tuple[int, int]) -> list[dict]:
    """Enkripsi per karakter dalam bentuk terstruktur (untuk tabel di web)."""
    e, n = public_key
    values = text_to_ascii(plaintext)
    if n <= 127:
        raise ValueError("Modulus n harus lebih besar dari 127.")
    rows = []
    for char, value in zip(plaintext, values):
        steps: list[str] = []
        cipher = mod_pow(value, e, n, steps)
        rows.append({"char": char, "ascii": value, "cipher": cipher, "steps": steps})
    return rows


def decrypt_rows(ciphertext_str: str, private_key: tuple[int, int], reveal: bool) -> list[dict]:
    """Dekripsi per karakter terstruktur. Jika reveal=False, langkah bit (yang membocorkan d) tidak disimpan."""
    d, n = private_key
    rows = []
    for cipher in _parse_ciphertext(ciphertext_str, n):
        steps: list[str] = []
        value = mod_pow(cipher, d, n, steps if reveal else None)
        if value > 127:
            raise ValueError("Hasil dekripsi bukan karakter ASCII yang valid.")
        rows.append({"cipher": cipher, "m": value, "char": chr(value), "steps": steps})
    return rows


# ----------------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------------

def insert_patient(db: list[dict], patient_id: int, nama: str, umur: int, diagnosis: str,
                   public_key: tuple[int, int], log: list[str] | None = None) -> dict:
    if any(row["id"] == patient_id for row in db):
        raise ValueError("ID pasien sudah digunakan.")
    if patient_id <= 0:
        raise ValueError("ID pasien harus berupa bilangan positif.")
    if not nama.strip():
        raise ValueError("Nama tidak boleh kosong.")
    if umur <= 0:
        raise ValueError("Umur harus berupa bilangan positif.")
    if not diagnosis.strip():
        raise ValueError("Diagnosis tidak boleh kosong.")
    ciphertext = encrypt_field(diagnosis, public_key, log)
    patient = {"id": patient_id, "nama": nama.strip(), "umur": umur, "diagnosis": ciphertext}
    db.append(patient)
    if log is not None:
        log.extend(["", "Plaintext → ASCII → RSA Encryption → Ciphertext → Database", f"Tersimpan: {patient}"])
    return patient


def print_database(db: list[dict]) -> None:
    print("=" * 72, "\nDATABASE EHR (Diagnosis disimpan sebagai ciphertext)\n" + "=" * 72)
    print(f"{'ID':<6}{'Nama':<24}{'Umur':<8}Diagnosis (ciphertext)")
    print("-" * 72)
    for row in db:
        print(f"{row['id']:<6}{row['nama']:<24}{row['umur']:<8}{row['diagnosis']}")
    print("=" * 72)


# ----------------------------------------------------------------------------
# CLI (tanpa login/role)
# ----------------------------------------------------------------------------

def _positive_int(prompt: str) -> int:
    raw = input(prompt).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("Nilai harus berupa angka bulat.") from exc
    if value <= 0:
        raise ValueError("Nilai harus lebih besar dari nol.")
    return value


def run_cli() -> None:
    db: list[dict] = []
    public_key = private_key = None
    while True:
        print("\n" + "=" * 54 + "\n ELECTRONIC HEALTH RECORD — RSA FIELD ENCRYPTION\n" + "=" * 54)
        print("1. Generate RSA Key Pair\n2. Input Rekam Medis Pasien\n3. Lihat Tabel Database Mentah\n4. Lihat Rekam Medis Terdekripsi\n5. Keluar")
        choice = input("\nPilih menu: ").strip()
        try:
            if choice == "1":
                if db:
                    raise ValueError("Key tidak dapat diganti selama database berisi data.")
                public_key, private_key, detail = generate_keys()
                print(key_generation_log(detail))
            elif choice == "2":
                if public_key is None:
                    raise ValueError("Buat RSA key pair terlebih dahulu.")
                log: list[str] = []
                patient = insert_patient(db, _positive_int("ID Pasien: "), input("Nama: "),
                                         _positive_int("Umur: "), input("Diagnosis: "), public_key, log)
                print("\n".join(log), f"\nData pasien {patient['id']} tersimpan.")
            elif choice == "3":
                print_database(db)
            elif choice == "4":
                if private_key is None:
                    raise ValueError("Buat RSA key pair terlebih dahulu.")
                if not db:
                    raise ValueError("Database masih kosong.")
                for row in db:
                    log = []
                    diagnosis = decrypt_field(row["diagnosis"], private_key, log)
                    print("\n".join(log))
                    print(f"\nID        : {row['id']}\nNama      : {row['nama']}\nUmur      : {row['umur']}\nDiagnosis : {diagnosis}")
            elif choice == "5":
                print("Program selesai.")
                return
            else:
                raise ValueError("Pilih menu 1 sampai 5.")
        except ValueError as exc:
            print(f"Error: {exc}")


# ----------------------------------------------------------------------------
# Web
# ----------------------------------------------------------------------------

CSS = """
*{box-sizing:border-box}
 :root{color-scheme:light;--ink:#202c26;--muted:#68756d;--green:#294d3b;--green-deep:#19392e;--red:#a74c3c;--paper:#fffefa;--line:#d8dfd7;--canvas:#edf0e9}
body{margin:0;background:var(--canvas);color:var(--ink);font:15px/1.55 "Trebuchet MS","Segoe UI",sans-serif}
main{max-width:1160px;margin:0 auto;padding:30px 30px 44px}
.masthead{display:flex;align-items:center;gap:15px;border-bottom:1px solid #bdc8bd;padding:4px 0 19px;margin-bottom:24px}
.brand-mark{display:grid;place-items:center;width:46px;height:46px;background:var(--green-deep);color:#fffefa;font:700 17px Georgia,serif;flex:none}
.eyebrow{margin:0 0 3px!important;color:var(--red)!important;font-size:10px!important;font-weight:800;letter-spacing:1.6px;text-transform:uppercase}
h1{font:500 30px/1.1 Georgia,"Times New Roman",serif;letter-spacing:0;margin:0}
.masthead p:last-child{margin:5px 0 0;color:var(--muted);font-size:13px}
h2{font:500 23px/1.2 Georgia,"Times New Roman",serif;letter-spacing:0;margin:0 0 14px}
h3{font-size:15px;margin:20px 0 8px}
p{color:var(--muted);margin:7px 0}
.card{background:var(--paper);border:1px solid var(--line);border-radius:2px;padding:22px 24px;margin:15px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:1px;background:#bdc8bd;border:1px solid #bdc8bd;margin:16px 0}
.stat{background:var(--paper);padding:14px 17px}
.stat b{display:block;font:500 26px Georgia,serif;color:var(--green-deep)}
.stat span{font-size:12px;color:var(--muted)}
.userbar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;border-top:0;border-left:4px solid var(--red)}
.userbar form{margin:0}
label{display:block;margin:12px 0 5px;color:var(--ink);font-size:13px;font-weight:700}
input{width:100%;min-height:43px;padding:9px 11px;border:1px solid #bdc8bd;border-radius:2px;background:#fff;color:var(--ink);font:inherit}
input:focus{outline:2px solid #d8a095;border-color:var(--red)}
button{background:var(--green);color:white;border:0;border-radius:2px;padding:11px 17px;font:700 13px "Trebuchet MS","Segoe UI",sans-serif;cursor:pointer;margin-top:14px}
button:hover{background:var(--green-deep)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:10px 11px;border-bottom:1px solid #e1e5de;vertical-align:top}
th{background:#f0f2ec;color:#56665b;font-size:11px;text-transform:uppercase;letter-spacing:.7px}
td:last-child{overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f0f2ec;padding:12px;margin:8px 0;font-size:13px}
.mono{font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere;color:#285744}
.msg{font-weight:700;color:#8e392e;background:#f7e9e4;border-left:3px solid var(--red);padding:10px 13px}
.msg.ok{color:#294d3b;background:#e7eee6;border-color:var(--green)}
.flow{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:17px 0 20px;color:#78847b;font-size:12px}
.flow span{background:transparent;border-bottom:1px solid #aebcaf;padding:4px 7px;color:var(--green-deep);font-weight:700}
.kv td:first-child{width:210px;font-weight:700}
.badge{display:inline-block;padding:2px 7px;font-size:11px;font-weight:700;text-transform:uppercase}
.badge.ok{background:#e2ece1;color:#294d3b}
.badge.bad{background:#f4e2dd;color:#963f32}
.badge.role{background:#e8ece4;color:#294d3b}
.secret{color:#963f32;font-style:italic}
.box{background:#f2f3ed;border-left:2px solid #b6c3b4;padding:13px}
.box b{display:block;font-size:11px;color:var(--muted);margin-bottom:5px;text-transform:uppercase}
details summary{cursor:pointer;color:var(--green);font-weight:700}
small{color:var(--muted)}
.page-foot{border-top:1px solid #bdc8bd;margin-top:27px;padding-top:12px;font-size:12px}
.login-layout{display:grid;grid-template-columns:minmax(260px,.85fr) minmax(340px,1.15fr);max-width:900px;margin:28px auto 0;background:var(--paper);border:1px solid var(--line)}
.login-page{min-height:100svh;display:flex;flex-direction:column}
.login-page .login-layout{width:min(100%,960px);margin:auto}
.login-aside{position:relative;overflow:hidden;background:var(--green-deep);color:#f7f5ed;padding:35px 32px;display:flex;flex-direction:column;justify-content:center;min-height:360px}
.login-aside:after{content:"RM";position:absolute;right:14px;bottom:-48px;color:rgba(247,245,237,.07);font:700 190px/.9 Georgia,serif;pointer-events:none}
.login-aside>div{position:relative;z-index:1}
.login-aside .eyebrow{color:#db9a82!important}
.login-aside h2{font-size:29px;margin:9px 0 12px}
.login-aside p{color:#d4ddd3}
.role-list{border-top:1px solid #526d5f;margin-top:28px;padding-top:13px}
.login-form{padding:35px 38px}
.login-form h2{font-size:25px}
.login-form button{width:100%;margin-top:20px}
@media(max-width:700px){main{padding:19px 14px 30px}.masthead{align-items:flex-start}.brand-mark{width:42px;height:42px}h1{font-size:26px}.login-layout{grid-template-columns:1fr;margin-top:14px}.login-aside{min-height:auto;padding:24px}.login-form{padding:24px}.role-list{margin-top:18px}.card{padding:18px 15px;overflow-x:auto}.flow{gap:3px}.flow span{padding:4px 5px}table{min-width:520px}}
"""

FLOW = ('<div class="flow"><span>Teks asli</span>→<span>Kode ASCII</span>→<span>RSA: c = m<sup>e</sup> mod n</span>'
    '→<span>Teks sandi</span>→<span>Penyimpanan</span>→<span>RSA: m = c<sup>d</sup> mod n</span>'
    '→<span>Teks asli</span></div>')


def _page(title: str, body: str, message: str = "", error: bool = False) -> bytes:
    msg_class = "msg" if error else "msg ok"
    msg_html = f'<p class="{msg_class}">{escape(message)}</p>' if message else ""
    flow_html = "" if "login-layout" in body else FLOW
    html = (f'<!doctype html><html lang="id"><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{escape(title)}</title><style>{CSS}</style>'
            f'<main class="{"login-page" if "login-layout" in body else "app-page"}"><header class="masthead"><div class="brand-mark">RM</div><div>'
            f'<p class="eyebrow">Orylda Hospital</p><h1>Ruang Rekam Medis</h1>'
            f'<p>Catatan pasien</p></div></header>'
            f'{flow_html}{msg_html}{body}'
            f'</main></html>')
    return html.encode("utf-8")


def _card(title: str, inner: str) -> str:
    return f"<section class='card'><h2>{title}</h2>{inner}</section>"


def _show_char(char: str) -> str:
    if char == " ":
        return "(spasi)"
    return escape(char) if char.isprintable() else "·"


def _steps_cell(steps: list[str]) -> str:
    text = escape(chr(10).join(steps))
    return f"<details><summary>lihat langkah</summary><pre>{text}</pre></details>"


def _to_int(raw: str, label: str) -> int:
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{label} harus berupa angka bulat.") from None


def _encrypt_result_html(rows: list[dict], public_key: tuple[int, int]) -> str:
    e, n = public_key
    body = "".join(
        f"<tr><td>{_show_char(r['char'])}</td><td>{r['ascii']}</td>"
        f"<td class='mono'>{r['ascii']}<sup>{e}</sup> mod {n}</td>"
        f"<td class='mono'>{r['cipher']}</td><td>{_steps_cell(r['steps'])}</td></tr>"
        for r in rows)
    return _card("Hasil enkripsi per karakter",
                 "<table><thead><tr><th>Karakter</th><th>Kode ASCII (m)</th><th>Rumus RSA</th>"
                 f"<th>Teks sandi (c)</th><th>Langkah hitung</th></tr></thead><tbody>{body}</tbody></table>")


def _decrypt_result_html(patient: dict, rows: list[dict], key: tuple[int, int]) -> str:
    d, n = key
    plain = "".join(r["char"] for r in rows)
    if SHOW_SECRETS:
        head = ("<th>Teks sandi (c)</th><th>m = c^d mod n</th><th>Kode ASCII (m)</th>"
            "<th>Karakter</th><th>Langkah hitung</th>")
        body = "".join(
            f"<tr><td class='mono'>{r['cipher']}</td><td class='mono'>{r['cipher']}<sup>{d}</sup> mod {n}</td>"
            f"<td>{r['m']}</td><td>{_show_char(r['char'])}</td><td>{_steps_cell(r['steps'])}</td></tr>"
            for r in rows)
    else:
        head = "<th>Teks sandi (c)</th><th>Operasi</th><th>Kode ASCII (m)</th><th>Karakter</th>"
        body = "".join(
            f"<tr><td class='mono'>{r['cipher']}</td><td class='mono'>c<sup>d</sup> mod {n} "
            f"<span class='secret'>(d tidak ditampilkan)</span></td>"
            f"<td>{r['m']}</td><td>{_show_char(r['char'])}</td></tr>"
            for r in rows)
    return _card(
        "Diagnosis setelah dibuka",
        f"<p>Pasien ID {patient['id']} — {escape(patient['nama'])}, {patient['umur']} tahun.</p>"
        "<div class='grid'>"
        f"<div class='box'><b>Tersimpan sebagai teks sandi</b><span class='mono'>{escape(patient['diagnosis'])}</span></div>"
        f"<div class='box'><b>Diagnosis terbaca</b>{escape(plain)}</div></div>"
        f"<h3>Rincian pembukaan per karakter</h3><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")


def run_web(host: str, port: int) -> None:
    db: list[dict] = []
    audit: list[tuple[str, str, str]] = []  # (waktu, pelaku, aksi)
    state: dict = {"public": None, "private": None, "detail": None}
    empty_row = '<tr><td colspan="4">Belum ada data.</td></tr>'

    add_user("admin", "admin123", "admin")
    add_user("dokter", "dokter123", "dokter")
    add_user("staf", "staf123", "staf")

    def note(actor: str, text: str) -> None:
        audit.append((datetime.now().strftime("%H:%M:%S"), actor, text))

    def key_section() -> str:
        button = "<form method='post' action='/keys'><button>Buat pasangan kunci</button></form>"
        detail = state["detail"]
        if detail is None:
            return _card("Pengaturan kunci RSA", button + "<p>Pasangan kunci belum dibuat.</p>")
        p, q, n, phi, e, d = (detail[k] for k in ("p", "q", "n", "phi", "e", "d"))
        ok_badge = '<span class="badge ok">terpenuhi</span>'
        bad_badge = '<span class="badge bad">gagal</span>'
        gcd_ok = gcd(e, phi) == 1
        inv_ok = (e * d) % phi == 1
        secret = "<span class='secret'>disembunyikan</span>"
        if SHOW_SECRETS:
            items = [("p", str(p)), ("q", str(q)), ("n = p × q", f"{p} × {q} = {n}"),
                     ("phi(n) = (p-1)(q-1)", f"{p - 1} × {q - 1} = {phi}"), ("e", str(e)),
                     ("d = e⁻¹ mod phi(n)", str(d)), ("Kunci publik (e, n)", f"({e}, {n})"),
                     ("Kunci privat (d, n)", f"({d}, {n})")]
            kv = "".join(f"<tr><td>{escape(k)}</td><td class='mono'>{escape(v)}</td></tr>" for k, v in items)
            extra = ("<details><summary>Langkah algoritma Euclid diperluas</summary>"
                     f"<pre>{escape(chr(10).join(extended_euclid_log(e, phi)))}</pre></details>")
        else:
            items = [("n = p × q", str(n)), ("e", str(e)), ("Kunci publik (e, n)", f"({e}, {n})")]
            kv = "".join(f"<tr><td>{escape(k)}</td><td class='mono'>{escape(v)}</td></tr>" for k, v in items)
            kv += (f"<tr><td>p, q, phi(n)</td><td>{secret}</td></tr>"
                   f"<tr><td>Kunci privat (d, n)</td><td>{secret} (disimpan di server)</td></tr>")
            extra = "<p><small>Rincian pembangkitan kunci dicetak di terminal server.</small></p>"
        verif = (f"<p>Verifikasi: gcd(e, phi) = 1 {ok_badge if gcd_ok else bad_badge} &nbsp; "
                 f"(e × d) mod phi = 1 {ok_badge if inv_ok else bad_badge}</p>")
        return _card("Pengaturan kunci RSA", f"{button}<table class='kv'><tbody>{kv}</tbody></table>{verif}{extra}")

    def stats_section() -> str:
        key_status = "Sudah dibuat" if state["detail"] else "Belum dibuat"
        return ("<div class='stats'>"
                f"<div class='stat'><b>{key_status}</b><span>Status pasangan kunci</span></div>"
                f"<div class='stat'><b>{len(db)}</b><span>Jumlah catatan pasien</span></div>"
                f"<div class='stat'><b>{len(audit)}</b><span>Aktivitas tercatat</span></div></div>")

    def audit_section() -> str:
        rows = "".join(
            f"<tr><td>{i}</td><td>{escape(t)}</td><td>{escape(who)}</td><td>{escape(act)}</td></tr>"
            for i, (t, who, act) in enumerate(audit, 1))
        empty = '<tr><td colspan="4">Belum ada catatan.</td></tr>'
        return _card("Riwayat aktivitas",
                 "<table><thead><tr><th>No.</th><th>Waktu</th><th>Pengguna</th><th>Aktivitas</th></tr></thead>"
                     f"<tbody>{rows or empty}</tbody></table>")

    class Handler(BaseHTTPRequestHandler):
        def respond(self, body: str, message: str = "", status: int = 200) -> None:
            payload = _page("Ruang Rekam Medis", body, message, error=status >= 400)
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)

        def redirect(self, location: str, cookie: str | None = None) -> None:
            self.send_response(303)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()

        def current_user(self) -> str | None:
            token = parse_cookie(self.headers.get("Cookie", "")).get("sid", "")
            return SESSIONS.get(token)

        def role_of(self, user: str | None) -> str | None:
            return USERS[user]["role"] if user else None

        def require(self, role: str | None, perm: str) -> None:
            if role is None or perm not in PERMISSIONS[role]:
                raise PermissionError("Akses ditolak: role Anda tidak punya izin untuk aksi ini.")

        def _login_form(self) -> str:
            return ("<section class='login-layout'>"
                    "<aside class='login-aside'><div><p class='eyebrow'>Login akun</p>"
                    "<h2>Ruang Rekam Medis</h2>"
                    "<p>Selamat Datang di Orylda Hospital.</p></div></aside>"
                    "<div class='login-form'><p class='eyebrow'>Ruang Rekam Medis</p><h2>Masuk</h2>"
                    "<form method='post' action='/login'>"
                    "<label>Nama pengguna</label><input name='username' autocomplete='username' required>"
                    "<label>Kata sandi</label><input name='password' type='password' autocomplete='current-password' required>"
                    "<button>Masuk</button></form>"
                    "</div></section>")

        def _body(self, user: str | None, enc_html: str = "", dec_html: str = "") -> str:
            role = self.role_of(user)
            if role is None:
                return self._login_form()
            perms = PERMISSIONS[role]
            out = ["<section class='card userbar'><div>"
                   f"<b>{escape(user)}</b> <span class='badge role'>{escape(role)}</span>"
                   f"<p>{escape(ROLE_INFO[role])}</p></div>"
                   "<form method='post' action='/logout'><button>Keluar</button></form></section>"]
            if "keys" in perms:
                out.append(stats_section())
                out.append(key_section())
            if "insert" in perms:
                out.append(_card("Tambah catatan pasien",
                                 "<form method='post' action='/patients'><div class='grid'><div>"
                                 "<label>Nomor pasien</label><input name='id' type='number' min='1' required>"
                                 "<label>Nama</label><input name='nama' required></div><div>"
                                 "<label>Umur</label><input name='umur' type='number' min='1' required>"
                                 "<label>Diagnosis (karakter ASCII)</label><input name='diagnosis' required></div></div>"
                                 "<button>Simpan catatan</button></form>"))
                out.append(enc_html)
            if "view_raw" in perms:
                rows = "".join(
                    f"<tr><td>{r['id']}</td><td>{escape(r['nama'])}</td><td>{r['umur']}</td>"
                    f"<td class='mono'>{escape(r['diagnosis'])}</td></tr>" for r in db)
                out.append(_card("Catatan tersimpan",
                                 "<p>Nama dan umur masih terbaca untuk diagnosis disimpan dalam bentuk teks sandi.</p>"
                                 "<table><thead><tr><th>ID</th><th>Nama</th><th>Umur</th>"
                                 "<th>Diagnosis tersandi</th></tr></thead>"
                                 f"<tbody>{rows or empty_row}</tbody></table>"))
            if "decrypt" in perms:
                out.append(_card("Buka diagnosis pasien",
                                 "<form method='post' action='/decrypt'><label>Nomor pasien</label>"
                                 "<input name='id' type='number' min='1' required>"
                                 "<button>Buka diagnosis</button></form>"))
                out.append(dec_html)
            if "audit" in perms:
                out.append(audit_section())
            return "".join(out)

        def do_GET(self) -> None:
            self.respond(self._body(self.current_user()))

        def do_POST(self) -> None:
            try:
                length = min(int(self.headers.get("Content-Length", "0")), 100_000)
            except ValueError:
                length = 0
            values = parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
            get = lambda name: values.get(name, [""])[0].strip()

            if self.path == "/login":
                username = get("username")
                role = verify_user(username, get("password"))
                if role is None:
                    note("anonim", f"login gagal untuk username '{username}'")
                    self.respond(self._login_form(), "Nama pengguna atau kata sandi tidak cocok.", 401)
                    return
                token = new_session_token()
                SESSIONS[token] = username
                note(f"{username} ({role})", "login")
                self.redirect("/", f"sid={token}; HttpOnly; SameSite=Strict; Path=/")
                return
            if self.path == "/logout":
                SESSIONS.pop(parse_cookie(self.headers.get("Cookie", "")).get("sid", ""), None)
                self.redirect("/", "sid=; Max-Age=0; Path=/")
                return

            user = self.current_user()
            role = self.role_of(user)
            actor = f"{user} ({role})" if user else "anonim"
            enc_html = dec_html = ""
            try:
                if self.path == "/keys":
                    self.require(role, "keys")
                    if db:
                        raise ValueError("Key tidak dapat diganti selama database berisi data.")
                    state["public"], state["private"], state["detail"] = generate_keys()
                    print(key_generation_log(state["detail"]))  # log lengkap hanya di terminal server
                    note(actor, "membuat key pair")
                    message = "Pasangan kunci berhasil dibuat."
                elif self.path == "/patients":
                    self.require(role, "insert")
                    if state["public"] is None:
                        raise ValueError("Buat key pair terlebih dahulu (oleh admin).")
                    patient = insert_patient(db, _to_int(get("id"), "ID pasien"), get("nama"),
                                             _to_int(get("umur"), "Umur"), get("diagnosis"), state["public"])
                    enc_html = _encrypt_result_html(encrypt_rows(get("diagnosis"), state["public"]), state["public"])
                    note(actor, f"menyimpan pasien ID {patient['id']}")
                    message = f"Pasien {patient['id']} tersimpan dengan diagnosis terenkripsi."
                elif self.path == "/decrypt":
                    self.require(role, "decrypt")
                    if state["private"] is None:
                        raise ValueError("Key pair belum dibuat oleh admin.")
                    pid = _to_int(get("id"), "ID pasien")
                    patient = next((r for r in db if r["id"] == pid), None)
                    if patient is None:
                        raise ValueError("ID pasien tidak ditemukan.")
                    rows = decrypt_rows(patient["diagnosis"], state["private"], SHOW_SECRETS)
                    dec_html = _decrypt_result_html(patient, rows, state["private"])
                    note(actor, f"mendekripsi pasien ID {pid}")
                    message = "Dekripsi selesai."
                else:
                    raise ValueError("Rute tidak ditemukan.")
                self.respond(self._body(user, enc_html, dec_html), message)
            except PermissionError as exc:
                note(actor, f"AKSES DITOLAK ke {self.path}")
                self.respond(self._body(user), str(exc), 403)
            except (ValueError, TypeError) as exc:
                self.respond(self._body(user), str(exc), 400)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = HTTPServer((host, port), Handler)
    print(f"Web EHR berjalan di http://{host}:{port} (Ctrl+C untuk berhenti)")
    print("Akun demo: admin/admin123, dokter/dokter123, staf/staf123")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer dihentikan.")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulasi EHR dengan RSA manual")
    parser.add_argument("--web", action="store_true", help="jalankan UI web localhost")
    parser.add_argument("--host", default="127.0.0.1", help="alamat bind web (default: localhost)")
    parser.add_argument("--port", type=int, default=8000, help="port web (default: 8000)")
    args = parser.parse_args()
    if args.web:
        run_web(args.host, args.port)
    else:
        run_cli()


if __name__ == "__main__":
    main()