"""Educational EHR demo: manual RSA, CLI, and a localhost web UI that shows every RSA stage."""

from __future__ import annotations

import argparse
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from random import SystemRandom
from urllib.parse import parse_qs


_RNG = SystemRandom()


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


def mod_pow(base: int, exp: int, mod: int, log: list[str] | None = None) -> int:
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


def decrypt_rows(ciphertext_str: str, private_key: tuple[int, int]) -> list[dict]:
    """Dekripsi per karakter dalam bentuk terstruktur (untuk tabel di web)."""
    d, n = private_key
    rows = []
    for cipher in _parse_ciphertext(ciphertext_str, n):
        steps: list[str] = []
        value = mod_pow(cipher, d, n, steps)
        if value > 127:
            raise ValueError("Hasil dekripsi bukan karakter ASCII yang valid (key kemungkinan salah).")
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
# CLI
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
body{margin:0;background:#f3f6f8;color:#17212b;font:15px/1.5 system-ui,sans-serif}
main{max-width:980px;margin:36px auto;padding:0 18px}
h1{font-size:25px;margin:0}
h2{font-size:18px;margin:0 0 12px}
h3{font-size:15px;margin:14px 0 6px}
p{color:#52616d;margin:6px 0}
.card{background:white;border:1px solid #dfe6eb;border-radius:10px;padding:18px;margin:16px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}
label{display:block;margin:9px 0 4px;font-weight:600}
input{width:100%;padding:9px;border:1px solid #cbd5dc;border-radius:6px}
button{background:#145c78;color:white;border:0;padding:10px 14px;border-radius:6px;cursor:pointer;margin-top:12px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 9px;border-bottom:1px solid #e7ecef;vertical-align:top}
th{font-size:13px;color:#52616d}
td:last-child{overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7f8;padding:12px;border-radius:6px;margin:8px 0;font-size:13px}
.mono{font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere}
.msg{font-weight:600;color:#9b321f}
.msg.ok{color:#1b6b3a}
.flow{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:14px 0}
.flow span{background:#e4eef3;border:1px solid #cfdde5;border-radius:6px;padding:4px 10px;font-size:13px}
.kv td:first-child{width:200px;font-weight:600}
.badge{display:inline-block;border-radius:6px;padding:1px 8px;font-size:13px;font-weight:600}
.badge.ok{background:#dff3e6;color:#1b6b3a}
.badge.bad{background:#fbe0dc;color:#9b321f}
.box{background:#f5f7f8;border-radius:8px;padding:12px}
.box b{display:block;font-size:13px;color:#52616d;margin-bottom:4px}
details summary{cursor:pointer;color:#145c78}
small{color:#65737e}
"""

FLOW = ('<div class="flow"><span>Plaintext</span>→<span>ASCII</span>→<span>RSA: c = m<sup>e</sup> mod n</span>'
        '→<span>Ciphertext</span>→<span>Database</span>→<span>RSA: m = c<sup>d</sup> mod n</span>'
        '→<span>Plaintext</span></div>')


def _page(title: str, body: str, message: str = "", error: bool = False) -> bytes:
    msg_class = "msg" if error else "msg ok"
    msg_html = f'<p class="{msg_class}">{escape(message)}</p>' if message else ""
    html = (f'<!doctype html><html lang="id"><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{escape(title)}</title><style>{CSS}</style>'
            f'<main><h1>Electronic Health Record</h1>'
            f'<p>Implementation RSA - Database Field Encryption for Healthcare System.</p>'
            f'{FLOW}{msg_html}{body}'
            f'<small>Simulasi lokal, bukan untuk data pasien nyata atau penggunaan produksi. '
            f'Private key ditampilkan hanya untuk keperluan demonstrasi edukasi.</small></main></html>')
    return html.encode("utf-8")


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
    return ("<section class='card'><h2>Hasil enkripsi (per karakter)</h2>"
            "<table><thead><tr><th>Karakter</th><th>ASCII (m)</th><th>c = m^e mod n</th>"
            f"<th>Ciphertext (c)</th><th>Square-and-Multiply</th></tr></thead><tbody>{body}</tbody></table>"
            "</section>")


def _decrypt_result_html(patient: dict, rows: list[dict], key: tuple[int, int], from_input: bool) -> str:
    d, n = key
    plain = "".join(r["char"] for r in rows)
    source = "key yang kamu masukkan" if from_input else "key milik server"
    note = ("<p>Jika key yang dimasukkan salah, hasilnya berupa error atau teks yang tidak bermakna.</p>"
            if from_input else "")
    body = "".join(
        f"<tr><td class='mono'>{r['cipher']}</td><td class='mono'>{r['cipher']}<sup>{d}</sup> mod {n}</td>"
        f"<td>{r['m']}</td><td>{_show_char(r['char'])}</td><td>{_steps_cell(r['steps'])}</td></tr>"
        for r in rows)
    return ("<section class='card'><h2>Hasil dekripsi</h2>"
            f"<p>Pasien ID {patient['id']} — {escape(patient['nama'])}, {patient['umur']} tahun. Memakai {source}.</p>"
            "<div class='grid'>"
            f"<div class='box'><b>Di database (ciphertext)</b><span class='mono'>{escape(patient['diagnosis'])}</span></div>"
            f"<div class='box'><b>Hasil dekripsi (plaintext)</b>{escape(plain)}</div></div>"
            f"{note}<h3>Dekripsi per karakter</h3>"
            "<table><thead><tr><th>Ciphertext (c)</th><th>m = c^d mod n</th><th>ASCII (m)</th>"
            f"<th>Karakter</th><th>Square-and-Multiply</th></tr></thead><tbody>{body}</tbody></table></section>")


def run_web(host: str, port: int) -> None:
    db: list[dict] = []
    state: dict = {"public": None, "private": None, "detail": None}
    empty_row = '<tr><td colspan="4">Belum ada data.</td></tr>'

    def key_section() -> str:
        detail = state["detail"]
        if detail is None:
            info = "<p>Key pair belum dibuat.</p>"
        else:
            p, q, n, phi, e, d = (detail[k] for k in ("p", "q", "n", "phi", "e", "d"))
            gcd_ok = gcd(e, phi) == 1
            inv_ok = (e * d) % phi == 1
            ok_badge = '<span class="badge ok">terpenuhi</span>'
            bad_badge = '<span class="badge bad">gagal</span>'
            items = [
                ("p", str(p)), ("q", str(q)),
                ("n = p × q", f"{p} × {q} = {n}"),
                ("phi(n) = (p-1)(q-1)", f"{p - 1} × {q - 1} = {phi}"),
                ("e", str(e)),
                ("d = e⁻¹ mod phi(n)", str(d)),
                ("Public Key (e, n)", f"({e}, {n})"),
                ("Private Key (d, n)", f"({d}, {n})"),
            ]
            kv = "".join(f"<tr><td>{escape(k)}</td><td class='mono'>{escape(v)}</td></tr>" for k, v in items)
            euclid = escape(chr(10).join(extended_euclid_log(e, phi)))
            info = (f"<table class='kv'><tbody>{kv}</tbody></table>"
                    f"<p>Verifikasi: gcd(e, phi) = 1 {ok_badge if gcd_ok else bad_badge} &nbsp; "
                    f"(e × d) mod phi = 1 {ok_badge if inv_ok else bad_badge}</p>"
                    f"<details><summary>Langkah Extended Euclidean Algorithm</summary><pre>{euclid}</pre></details>")
        return ("<section class='card'><h2>1. Pembangkitan kunci RSA</h2>"
                "<form method='post' action='/keys'><button>Buat key pair</button></form>"
                f"{info}</section>")

    def render(enc_html: str = "", dec_html: str = "") -> str:
        rows = "".join(
            f"<tr><td>{r['id']}</td><td>{escape(r['nama'])}</td><td>{r['umur']}</td>"
            f"<td class='mono'>{escape(r['diagnosis'])}</td></tr>" for r in db)
        return (key_section()
                + "<section class='card'><h2>2. Input pasien</h2><form method='post' action='/patients'>"
                  "<div class='grid'><div><label>ID pasien</label><input name='id' type='number' min='1' required>"
                  "<label>Nama</label><input name='nama' required></div>"
                  "<div><label>Umur</label><input name='umur' type='number' min='1' required>"
                  "<label>Diagnosis (ASCII)</label><input name='diagnosis' required></div></div>"
                  "<button>Simpan terenkripsi</button></form></section>"
                + enc_html
                + "<section class='card'><h2>3. Database mentah</h2>"
                  "<p>Nama dan data administratif plaintext; diagnosis ciphertext.</p>"
                  "<table><thead><tr><th>ID</th><th>Nama</th><th>Umur</th><th>Diagnosis ciphertext</th></tr></thead>"
                  f"<tbody>{rows or empty_row}</tbody></table></section>"
                + "<section class='card'><h2>4. Dekripsi rekam medis</h2>"
                  "<form method='post' action='/decrypt'><label>ID pasien</label>"
                  "<input name='id' type='number' min='1' required>"
                  "<div class='grid'><div><label>Private key d (opsional)</label><input name='d'></div>"
                  "<div><label>Modulus n (opsional)</label><input name='n'></div></div>"
                  "<p><small>Kosongkan d dan n untuk memakai key dari server. Isi keduanya untuk mencoba key lain, "
                  "misalnya key yang salah, dan lihat hasilnya.</small></p>"
                  "<button>Dekripsi</button></form></section>"
                + dec_html)

    class Handler(BaseHTTPRequestHandler):
        def respond(self, body: str, message: str = "", status: int = 200) -> None:
            payload = _page("EHR RSA Demo", body, message, error=status >= 400)
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            self.respond(render())

        def do_POST(self) -> None:
            try:
                length = min(int(self.headers.get("Content-Length", "0")), 100_000)
            except ValueError:
                length = 0
            values = parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
            get = lambda name: values.get(name, [""])[0].strip()
            enc_html = dec_html = ""
            try:
                if self.path == "/keys":
                    if db:
                        raise ValueError("Key tidak dapat diganti selama database berisi data.")
                    state["public"], state["private"], state["detail"] = generate_keys()
                    print(key_generation_log(state["detail"]))
                    message = "Key pair berhasil dibuat."
                elif self.path == "/patients":
                    if state["public"] is None:
                        raise ValueError("Buat key pair terlebih dahulu.")
                    patient = insert_patient(db, _to_int(get("id"), "ID pasien"), get("nama"),
                                             _to_int(get("umur"), "Umur"), get("diagnosis"), state["public"])
                    enc_html = _encrypt_result_html(encrypt_rows(get("diagnosis"), state["public"]), state["public"])
                    message = f"Pasien {patient['id']} tersimpan dengan diagnosis terenkripsi."
                elif self.path == "/decrypt":
                    pid = _to_int(get("id"), "ID pasien")
                    patient = next((r for r in db if r["id"] == pid), None)
                    if patient is None:
                        raise ValueError("ID pasien tidak ditemukan.")
                    d_raw, n_raw = get("d"), get("n")
                    from_input = bool(d_raw or n_raw)
                    if from_input:
                        if not (d_raw and n_raw):
                            raise ValueError("Isi d dan n sekaligus, atau kosongkan keduanya.")
                        key = (_to_int(d_raw, "Nilai d"), _to_int(n_raw, "Nilai n"))
                    else:
                        if state["private"] is None:
                            raise ValueError("Buat key pair terlebih dahulu.")
                        key = state["private"]
                    rows = decrypt_rows(patient["diagnosis"], key)
                    dec_html = _decrypt_result_html(patient, rows, key, from_input)
                    message = "Dekripsi selesai."
                else:
                    raise ValueError("Rute tidak ditemukan.")
                self.respond(render(enc_html, dec_html), message)
            except (ValueError, TypeError) as exc:
                self.respond(render(), str(exc), 400)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = HTTPServer((host, port), Handler)
    print(f"Web EHR berjalan di http://{host}:{port} (Ctrl+C untuk berhenti)")
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

