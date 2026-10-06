"""Educational EHR demo: manual RSA, CLI, and a small localhost web UI."""

from __future__ import annotations

import argparse
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from random import SystemRandom
from urllib.parse import parse_qs


_RNG = SystemRandom()


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
            log.extend([f"\nCharacter : {char}", f"ASCII     : {value}", f"c = m^e mod n", f"c = {value}^{e} mod {n}", *steps, f"c = {cipher}"])
    return " ".join(output)


def decrypt_field(ciphertext_str: str, private_key: tuple[int, int], log: list[str] | None = None) -> str:
    d, n = private_key
    parts = ciphertext_str.split()
    if not parts:
        raise ValueError("Ciphertext tidak boleh kosong.")
    if any(not part.isdecimal() for part in parts):
        raise ValueError("Ciphertext harus berupa angka yang dipisahkan spasi.")
    values = [int(part) for part in parts]
    if any(value < 0 or value >= n for value in values):
        raise ValueError("Nilai ciphertext harus berada pada rentang 0 sampai n-1.")
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
            log.extend([f"\nCiphertext = {cipher}", f"m = c^d mod n", f"m = {cipher}^{d} mod {n}", *steps, f"m = {value}", f"ASCII {value} = {char}"])
    return "".join(chars)


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


def _page(title: str, body: str, message: str = "") -> bytes:
    safe_title, safe_message = escape(title), escape(message)
    html = f"""<!doctype html><html lang="id"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{safe_title}</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f3f6f8;color:#17212b;font:15px/1.5 system-ui,sans-serif}}main{{max-width:920px;margin:36px auto;padding:0 18px}}h1{{font-size:25px;margin:0}}h2{{font-size:18px;margin:0 0 12px}}p{{color:#52616d}}.card{{background:white;border:1px solid #dfe6eb;border-radius:10px;padding:18px;margin:16px 0}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}}label{{display:block;margin:9px 0 4px;font-weight:600}}input{{width:100%;padding:9px;border:1px solid #cbd5dc;border-radius:6px}}button{{background:#145c78;color:white;border:0;padding:10px 14px;border-radius:6px;cursor:pointer;margin-top:12px}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:9px;border-bottom:1px solid #e7ecef;vertical-align:top}}td:last-child{{overflow-wrap:anywhere}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7f8;padding:12px;border-radius:6px}}.msg{{color:#9b321f;font-weight:600}}small{{color:#65737e}}
</style><main><h1>Electronic Health Record</h1><p>Demo edukasi RSA — data disimpan di memori selama server berjalan.</p>{f'<p class="msg">{safe_message}</p>' if message else ''}{body}<small>Simulasi lokal, bukan untuk data pasien nyata atau penggunaan produksi.</small></main></html>"""
    return html.encode("utf-8")


def run_web(host: str, port: int) -> None:
    db: list[dict] = []
    public_key = private_key = None
    key_log = "RSA key belum dibuat."

    class Handler(BaseHTTPRequestHandler):
        def respond(self, body: str, message: str = "", status: int = 200) -> None:
            payload = _page("EHR RSA Demo", body, message)
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            rows = "".join(f"<tr><td>{row['id']}</td><td>{escape(row['nama'])}</td><td>{row['umur']}</td><td>{escape(row['diagnosis'])}</td></tr>" for row in db)
            body = f"""<div class="grid"><section class="card"><h2>1. Kunci RSA</h2><form method="post" action="/keys"><button>Buat key pair</button></form><pre>{escape(key_log)}</pre></section>
<section class="card"><h2>2. Input pasien</h2><form method="post" action="/patients"><label>ID pasien</label><input name="id" type="number" min="1" required><label>Nama</label><input name="nama" required><label>Umur</label><input name="umur" type="number" min="1" required><label>Diagnosis (ASCII)</label><input name="diagnosis" required><button>Simpan terenkripsi</button></form></section></div>
<section class="card"><h2>3. Database mentah</h2><p>Nama dan data administratif plaintext; diagnosis ciphertext.</p><table><thead><tr><th>ID</th><th>Nama</th><th>Umur</th><th>Diagnosis ciphertext</th></tr></thead><tbody>{rows or '<tr><td colspan="4">Belum ada data.</td></tr>'}</tbody></table></section>
<section class="card"><h2>4. Buka rekam medis</h2><form method="post" action="/decrypt"><label>ID pasien</label><input name="id" type="number" min="1" required><button>Dekripsi</button></form></section>"""
            self.respond(body)

        def do_POST(self) -> None:
            nonlocal public_key, private_key, key_log
            length = min(int(self.headers.get("Content-Length", "0")), 100_000)
            values = parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
            get = lambda name: values.get(name, [""])[0].strip()
            try:
                if self.path == "/keys":
                    if db:
                        raise ValueError("Key tidak dapat diganti selama database berisi data.")
                    public_key, private_key, detail = generate_keys()
                    key_log = key_generation_log(detail)
                    message = "Key pair berhasil dibuat."
                elif self.path == "/patients":
                    if public_key is None:
                        raise ValueError("Buat key pair terlebih dahulu.")
                    log: list[str] = []
                    row = insert_patient(db, int(get("id")), get("nama"), int(get("umur")), get("diagnosis"), public_key, log)
                    message = f"Pasien {row['id']} tersimpan. Detail proses enkripsi ditampilkan di bawah."
                    self.respond(self._body() + f"<section class='card'><h2>Log enkripsi</h2><pre>{escape(chr(10).join(log))}</pre></section>", message)
                    return
                elif self.path == "/decrypt":
                    if private_key is None:
                        raise ValueError("Buat key pair terlebih dahulu.")
                    patient = next((row for row in db if row["id"] == int(get("id"))), None)
                    if patient is None:
                        raise ValueError("ID pasien tidak ditemukan.")
                    log = []
                    diagnosis = decrypt_field(patient["diagnosis"], private_key, log)
                    details = f"<section class='card'><h2>Rekam medis terdekripsi</h2><p>ID: {patient['id']}<br>Nama: {escape(patient['nama'])}<br>Umur: {patient['umur']}<br>Diagnosis: {escape(diagnosis)}</p><h2>Log dekripsi</h2><pre>{escape(chr(10).join(log))}</pre></section>"
                    self.respond(self._body() + details, "Dekripsi berhasil.")
                    return
                else:
                    raise ValueError("Rute tidak ditemukan.")
                self.respond(self._body(), message)
            except (ValueError, TypeError) as exc:
                self.respond(self._body(), str(exc), 400)

        def _body(self) -> str:
            rows = "".join(f"<tr><td>{row['id']}</td><td>{escape(row['nama'])}</td><td>{row['umur']}</td><td>{escape(row['diagnosis'])}</td></tr>" for row in db)
            return f"""<div class="grid"><section class="card"><h2>1. Kunci RSA</h2><form method="post" action="/keys"><button>Buat key pair</button></form><pre>{escape(key_log)}</pre></section><section class="card"><h2>2. Input pasien</h2><form method="post" action="/patients"><label>ID pasien</label><input name="id" type="number" min="1" required><label>Nama</label><input name="nama" required><label>Umur</label><input name="umur" type="number" min="1" required><label>Diagnosis (ASCII)</label><input name="diagnosis" required><button>Simpan terenkripsi</button></form></section></div><section class="card"><h2>3. Database mentah</h2><table><thead><tr><th>ID</th><th>Nama</th><th>Umur</th><th>Diagnosis ciphertext</th></tr></thead><tbody>{rows or '<tr><td colspan="4">Belum ada data.</td></tr>'}</tbody></table></section><section class="card"><h2>4. Buka rekam medis</h2><form method="post" action="/decrypt"><label>ID pasien</label><input name="id" type="number" min="1" required><button>Dekripsi</button></form></section>"""

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
