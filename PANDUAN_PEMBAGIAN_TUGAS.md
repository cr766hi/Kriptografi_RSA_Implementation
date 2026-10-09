# Panduan Pembagian Tugas Proyek EHR RSA

## Potongan Helper Tambahan

### Anggota 1: log pembangkitan kunci

`extended_euclid_log()` dan `key_generation_log()` membuat log langkah hitung untuk demo dan berada berdekatan dengan fungsi pembangkitan kunci:

```python
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
```

### Anggota 2: helper enkripsi dan database

`encrypt_rows()` membentuk rincian hasil enkripsi untuk tabel web:

```python
def encrypt_rows(plaintext: str, public_key: tuple[int, int]) -> list[dict]:
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
```

`print_database()` menampilkan tabel mentah dengan diagnosis ciphertext:

```python
def print_database(db: list[dict]) -> None:
      print("=" * 72, "\nDATABASE EHR (Diagnosis disimpan sebagai ciphertext)\n" + "=" * 72)
      print(f"{'ID':<6}{'Nama':<24}{'Umur':<8}Diagnosis (ciphertext)")
      print("-" * 72)
      for row in db:
            print(f"{row['id']:<6}{row['nama']:<24}{row['umur']:<8}{row['diagnosis']}")
      print("=" * 72)
```
### Anggota 3: helper dekripsi dan CLI

Pada web, `decrypt_rows()` mengembalikan rincian per karakter untuk ditampilkan:

```python
def decrypt_rows(ciphertext_str: str, private_key: tuple[int, int], reveal: bool) -> list[dict]:
      d, n = private_key
      rows = []
      for cipher in _parse_ciphertext(ciphertext_str, n):
            steps: list[str] = []
            value = mod_pow(cipher, d, n, steps if reveal else None)
            if value > 127:
                  raise ValueError("Hasil dekripsi bukan karakter ASCII yang valid.")
            rows.append({"cipher": cipher, "m": value, "char": chr(value), "steps": steps})
      return rows
```

CLI memakai `decrypt_field()` untuk membuka data dari database.
`_positive_int()` menangani masukan bilangan bulat positif:

```python
def _positive_int(prompt: str) -> int:
      raw = input(prompt).strip()
      try:
            value = int(raw)
      except ValueError as exc:
            raise ValueError("Nilai harus berupa angka bulat.") from exc
      if value <= 0:
            raise ValueError("Nilai harus lebih besar dari nol.")
      return value
```

`main()` memilih CLI atau web berdasarkan argumen:
---

## Identitas dan pembagian

| Anggota | Nama | NIM | Fokus tugas |
|---|---|---|---|
| 1 | Christiano Ronaldo | 5027241025 | Pembangkitan kunci RSA dan matematika dasar |
| 2 | Erlinda Annisa Zahra | 5027241108 | Enkripsi diagnosis dan penyimpanan data |
| 3 | Oryza Qiara Ramadhani | 5027241084 | Dekripsi, CLI, integrasi, dan pengujian |

Proyek ini adalah simulasi Electronic Health Record (EHR). Diagnosis diubah menjadi ciphertext sebelum dimasukkan ke database, sedangkan ID, nama, dan umur tetap dapat dibaca. Program ditujukan untuk pembelajaran, bukan penyimpanan data medis sungguhan.

## Cara membaca struktur kode

Implementasi utama digabung dalam satu file, [ehr_rsa.py](ehr_rsa.py), agar bisa dijalankan sebagai program utuh. Karena itu, pembagian anggota adalah pembagian tanggung jawab terhadap bagian/fungsi, bukan pembagian menjadi tiga file Python terpisah. Fungsi matematika dan kriptografi juga dipakai bersama saat proses enkripsi dan dekripsi.

README proyek menggunakan `ehr_rsa.py` sebagai program utama. File [ehr_rsa_rbac.py](ehr_rsa_rbac.py) adalah varian demo yang menampilkan tahap RSA secara lengkap; sebelum mengambil screenshot atau demo, pastikan kelompok memakai file dan perilaku yang sama.

## Anggota 1: Pembangkitan Kunci dan Matematika Dasar

### Tujuan bagian

Membuat pasangan kunci publik dan privat yang dibutuhkan oleh seluruh proses RSA. Anggota ini menjelaskan bagaimana bilangan prima dan algoritma Euclid digunakan untuk membentuk kunci.

### Fungsi yang menjadi fokus

- `gcd(a, b)`: mencari FPB memakai algoritma Euclid. Pada tiap iterasi, pasangan nilai diperbarui menjadi $(b, a \bmod b)$ sampai sisanya nol.
- `is_prime(n)`: menguji apakah suatu bilangan prima dengan pembagian kandidat pembagi ganjil.
- `generate_prime(min_val, max_val)`: memilih bilangan prima secara acak dari rentang yang ditentukan.
- `mod_inverse(e, phi)`: memakai Extended Euclidean Algorithm untuk mencari invers modular $d$, sehingga $(e \times d) \bmod \phi(n) = 1$.
- `generate_keys()`: memilih prima berbeda $p$ dan $q$, kemudian menghitung $n$, $\phi(n)$, $e$, dan $d$. Fungsi mengembalikan public key $(e,n)$, private key $(d,n)$, dan detail perhitungan untuk log/demo.
- `extended_euclid_log()` dan `key_generation_log()`: menyusun langkah hitung untuk diterangkan atau diperlihatkan saat demo.

### Urutan penjelasan saat presentasi

1. Pilih dua bilangan prima berbeda, $p$ dan $q$.
2. Hitung modulus $n = p \times q$.
3. Hitung totient $\phi(n) = (p-1)(q-1)$.
4. Pilih $e$ dengan $1 < e < \phi(n)$ dan $\gcd(e,\phi(n))=1$.
5. Cari $d$ sebagai invers modular $e$ terhadap $\phi(n)$.
6. Terangkan bahwa public key adalah $(e,n)$ dan private key adalah $(d,n)$.

### Bagian laporan

- Bab Dasar Teori RSA: bilangan prima, FPB, totient, invers modular, dan alur pembangkitan kunci.
- Bab Implementasi: uraian fungsi pembangkitan kunci beserta contoh output. Jelaskan arti $p$, $q$, $n$, $\phi(n)$, $e$, dan $d$.

### Bukti demo yang disiapkan

Tampilkan pembuatan key pair. Pastikan dapat menjelaskan pemeriksaan $\gcd(e,\phi(n))=1$ serta verifikasi $(e \times d) \bmod \phi(n)=1$. Nilai kunci berubah setiap program dijalankan karena pemilihannya acak.

## Anggota 2: Enkripsi dan Penyimpanan Database

### Tujuan bagian

Mengubah diagnosis menjadi angka ASCII, mengenkripsi setiap karakter menggunakan public key, lalu menyimpan ciphertext bersama data pasien lain dalam struktur database sederhana.

### Fungsi yang menjadi fokus

- `mod_pow(base, exp, mod, log)`: menghitung perpangkatan modular dengan metode square-and-multiply. Implementasi manual ini dipakai pada enkripsi maupun dekripsi.
- `text_to_ascii(text)`: mengubah tiap karakter diagnosis menjadi kode ASCII dan menolak karakter di luar rentang ASCII yang didukung.
- `encrypt_field(plaintext, public_key, log)`: mengenkripsi tiap kode ASCII dengan rumus $c = m^e \bmod n$, lalu menyimpan hasil sebagai deretan angka ciphertext.
- `encrypt_rows(plaintext, public_key)`: menyiapkan rincian enkripsi per karakter untuk tampilan tabel pada web.
- `insert_patient(...)`: memvalidasi ID, nama, umur, dan diagnosis; mengenkripsi diagnosis; lalu menambahkan record ke list database.
- `print_database(db)`: menampilkan isi database mentah, termasuk diagnosis dalam bentuk ciphertext.

Satu record pasien memiliki bentuk konseptual seperti berikut:

```text
{
  "id": 1,
  "nama": "Budi",
  "umur": 25,
  "diagnosis": "angka-ciphertext-dipisahkan-spasi"
}
```

### Urutan penjelasan saat presentasi

1. Pengguna memasukkan data pasien dan diagnosis plaintext.
2. Diagnosis dikonversi menjadi angka ASCII $m$.
3. Setiap $m$ dienkripsi memakai public key dengan $c = m^e \bmod n$.
4. Angka ciphertext disimpan pada field `diagnosis`; ID, nama, dan umur tetap plaintext.
5. Tabel database memperlihatkan perbedaan field yang dienkripsi dan yang tidak.

### Bagian laporan

- Bab Analisis dan Perancangan: alur sistem, struktur record/database, field yang dilindungi, dan alasan enkripsi parsial.
- Bab Implementasi: konversi ASCII, square-and-multiply, enkripsi, validasi input, dan penyimpanan record. Sertakan screenshot hasil input dan tabel ciphertext.

### Bukti demo yang disiapkan

Masukkan contoh diagnosis seperti `Influenza`, kemudian tunjukkan bahwa database berisi angka ciphertext, bukan kata tersebut. Jelaskan bahwa database yang dipakai adalah list di memori, sehingga datanya hilang setelah program berhenti.

## Anggota 3: Dekripsi, CLI, Integrasi, dan Pengujian

### Tujuan bagian

Mengembalikan ciphertext menjadi diagnosis plaintext menggunakan private key, menghubungkan fungsi-fungsi anggota lain ke alur program yang bisa dijalankan, dan memastikan input tidak valid ditangani dengan pesan kesalahan.

### Fungsi dan bagian yang menjadi fokus

- `_parse_ciphertext(ciphertext_str, n)`: memeriksa format ciphertext dan memastikan nilainya berada pada rentang $0$ sampai $n-1$.
- `decrypt_field(ciphertext_str, private_key, log)`: menghitung kembali setiap karakter memakai $m = c^d \bmod n$, lalu mengubah angka ASCII menjadi teks.
- `decrypt_rows(...)`: menyiapkan rincian hasil dekripsi per karakter untuk tampilan web.
- `_positive_int(prompt)`: membaca masukan bilangan bulat positif untuk CLI.
- `run_cli()`: menyediakan menu untuk membuat key pair, memasukkan pasien, melihat database, membuka diagnosis, atau keluar.
- `main()`: memilih mode program berdasarkan argumen yang diberikan.
- `run_web()` dan handler-nya: menghubungkan operasi RSA ke antarmuka web lokal. Pada `ehr_rsa.py`, versi web juga mengatur login dan hak akses peran.

### Urutan penjelasan saat presentasi

1. Ambil ciphertext pasien dari database.
2. Pecah ciphertext menjadi nilai angka dan validasi rentangnya.
3. Hitung $m = c^d \bmod n$ menggunakan private key.
4. Ubah kembali kode ASCII menjadi diagnosis yang dapat dibaca.
5. Tunjukkan bahwa diagnosis hasil dekripsi sama dengan teks sebelum dienkripsi.
6. Terangkan bagaimana CLI/web memanggil fungsi key generation, enkripsi, penyimpanan, dan dekripsi sebagai satu alur.

### Bagian laporan

- Bab Pendahuluan: latar belakang, rumusan masalah, tujuan, dan manfaat.
- Bab Implementasi dan Pengujian: dekripsi, menu CLI atau antarmuka web, integrasi modul, pengujian berhasil/gagal, serta penanganan error.
- Bab Penutup: kesimpulan dan saran pengembangan.

### Bukti demo yang disiapkan

Perlihatkan satu siklus lengkap dari pembuatan kunci sampai diagnosis dibuka kembali. Uji juga ID duplikat, umur bukan bilangan positif, diagnosis kosong, input non-ASCII, ciphertext tidak valid, dan operasi sebelum key pair dibuat.

## Alur integrasi bersama

Alur data utama program adalah:

```text
Generate key pair
      ↓
Input data pasien
      ↓
Diagnosis plaintext → ASCII → enkripsi dengan public key
      ↓
Simpan ciphertext ke database
      ↓
Ambil ciphertext → dekripsi dengan private key → diagnosis plaintext
```

Ketergantungan antartugas:

- Bagian anggota 1 menghasilkan public key untuk enkripsi dan private key untuk dekripsi.
- Bagian anggota 2 memakai public key dan fungsi `mod_pow()` untuk membuat ciphertext, lalu menyimpan record.
- Bagian anggota 3 memakai private key dan fungsi `mod_pow()` yang sama untuk memulihkan plaintext serta mengintegrasikan alur program.
- Semua anggota perlu menyepakati format key `(eksponen, modulus)`, representasi ciphertext sebagai angka yang dipisahkan spasi, dan batas input ASCII.

## Checklist sebelum presentasi

- Gunakan file utama yang konsisten dengan instruksi README, yaitu `ehr_rsa.py`.
- Jalankan CLI dengan `python ehr_rsa.py` atau web localhost dengan `python ehr_rsa.py --web`.
- Siapkan satu contoh data fiktif; jangan masukkan data pasien sungguhan.
- Pastikan diagnosis tampil sebagai ciphertext di database dan kembali menjadi teks yang sama setelah dekripsi.
- Jelaskan bahwa program memakai RSA sederhana per karakter dengan bilangan kecil untuk edukasi, bukan rancangan aman untuk penggunaan produksi.
- Jika menampilkan web RBAC, jelaskan pembatasan role pada versi `ehr_rsa.py`: admin mengelola key/audit, dokter dapat input dan dekripsi, staf dapat input tetapi tidak dekripsi.

## Batasan yang perlu disampaikan

Implementasi RSA ini hanya simulasi pendidikan: ukuran kunci kecil, enkripsi dilakukan per karakter tanpa padding modern, dan diagnosis dibatasi ke ASCII. Nama, ID, dan umur tetap terlihat. Database hanya berada di memori. Karena itu sistem tidak boleh digunakan untuk melindungi rekam medis nyata.

## Potongan kode per anggota

Contoh berikut diambil dari implementasi utama `ehr_rsa.py`, lalu dikelompokkan sesuai pembagian kerja.

### Anggota 1: fungsi matematika dan pembangkitan kunci

FPB Euclid dan pemeriksaan prima:

```python
def gcd(a: int, b: int) -> int:
      while b:
            a, b = b, a % b
      return abs(a)


def is_prime(n: int) -> bool:
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
```

Memilih prima dari rentang yang tersedia:

```python
def generate_prime(min_val: int = 257, max_val: int = 997) -> int:
      if min_val > max_val:
            raise ValueError("Batas minimum harus <= batas maksimum.")
      candidates = [n for n in range(min_val, max_val + 1) if is_prime(n)]
      if not candidates:
            raise ValueError("Rentang tidak memuat bilangan prima.")
      return _RNG.choice(candidates)
```

Invers modular dengan Extended Euclidean Algorithm:

```python
def mod_inverse(e: int, phi: int) -> int:
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
```

Membentuk public key dan private key:

```python
def generate_keys() -> tuple[tuple[int, int], tuple[int, int], dict[str, int]]:
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
```

`extended_euclid_log()` dan `key_generation_log()` membuat log langkah hitung untuk demo dan berada berdekatan dengan fungsi pembangkitan kunci.

### Anggota 2: square-and-multiply, enkripsi, dan database

Perpangkatan modular manual yang digunakan oleh enkripsi dan dekripsi:

```python
def mod_pow(base: int, exp: int, mod: int, log: list[str] | None = None) -> int:
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
```

Konversi diagnosis dan enkripsi per karakter:

```python
def text_to_ascii(text: str) -> list[int]:
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
```

Penyimpanan memvalidasi data, mengenkripsi diagnosis, lalu menambahkan record ke list:

```python
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
```

`encrypt_rows()` membentuk rincian hasil enkripsi untuk tabel web, sedangkan `print_database()` menampilkan tabel mentah dengan diagnosis ciphertext.

### Anggota 3: dekripsi dan integrasi CLI

Memvalidasi angka ciphertext sebelum diproses:

```python
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
```

Dekripsi dengan private key dan konversi kembali menjadi teks:

```python
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
```

Bagian inti menu CLI yang menghubungkan fungsi anggota 1, 2, dan 3:

```python
def run_cli() -> None:
      db: list[dict] = []
      public_key = private_key = None
      while True:
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
```

`_positive_int()` menangani masukan bilangan bulat positif. `main()` memilih CLI atau web berdasarkan argumen:

```python
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
```