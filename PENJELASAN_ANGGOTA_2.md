# Penjelasan Anggota 2: Enkripsi Diagnosis dan Penyimpanan Database

Dokumen ini dibuat untuk membantu demo presentasi kelompok. Fokusnya adalah bagian enkripsi diagnosis menggunakan RSA dan penyimpanan data pasien ke database dalam bentuk ciphertext.

---

## 1. Fungsi `mod_pow(base, exp, mod, log)`

```python
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
```

### Penjelasan
- Fungsi ini menghitung `base^exp mod mod` secara manual tanpa memakai fungsi bawaan `pow()`.
- Teknik yang dipakai adalah `square-and-multiply`.
- Prosesnya:
  1. Ambil bit dari exponent.
  2. Jika bit-nya `1`, kalikan hasil dengan basis.
  3. Lanjutkan dengan kuadratkan basis.
  4. Ulang sampai exponent habis.

### Kenapa penting?
Fungsi ini dipakai di RSA untuk perhitungan:
- Enkripsi: `c = m^e mod n`
- Dekripsi: `m = c^d mod n`

### Contoh demo
Jika:
- `base = 65`
- `exp = 7`
- `mod = 143`

Maka hasilnya adalah:

```python
mod_pow(65, 7, 143)
```

Hasilnya adalah nilai `65^7 mod 143` yang dipakai dalam proses RSA per karakter.

---

## 2. Fungsi `text_to_ascii(text)`

```python
def text_to_ascii(text: str) -> list[int]:
    """Convert characters to ASCII code points; reject non-ASCII input."""
    values = [ord(char) for char in text]
    if any(value > 127 for value in values):
        raise ValueError("Diagnosis harus berisi karakter ASCII (0–127).")
    return values
```

### Penjelasan
- Setiap karakter pada diagnosis akan diubah menjadi kode ASCII menggunakan `ord(char)`.
- Misalnya:
  - `I` → `73`
  - `n` → `110`
  - `f` → `102`
  - `l` → `108`
  - `u` → `117`
  - `e` → `101`
  - `n` → `110`
  - `z` → `122`

Jadi kata `Influenza` akan diubah menjadi deretan angka ASCII. Setelah itu, angka-angka itu akan dienkripsi satu per satu.

### Kenapa perlu?
Karena RSA bekerja pada bilangan numerik, bukan string langsung. Jadi diagnosis text harus diubah dulu menjadi angka.

### Contoh demo
```python
text_to_ascii("Influenza")
```

Output yang dihasilkan adalah:

```python
[73, 110, 102, 108, 117, 101, 110, 122, 97]
```

---

## 3. Fungsi `encrypt_field(plaintext, public_key, log)`

```python
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

### Penjelasan
Fungsi ini melakukan enkripsi diagnosis dari bentuk teks ke ciphertext.

Langkah-langkahnya:
1. Ambil `public_key = (e, n)`.
2. Ubah setiap karakter diagnosis ke kode ASCII.
3. Untuk setiap angka ASCII `m`, hitung:
   
   `c = m^e mod n`

4. Simpan hasil cipher untuk tiap karakter.
5. Gabungkan semua ciphertext dengan spasi.

### Contoh demo
Misalnya diagnosis:

```python
plaintext = "Influenza"
public_key = (5, 143)
```

Maka setiap huruf akan dienkripsi dengan persamaan RSA. Hasilnya berupa deretan angka seperti:

```python
"82 23 40 71 54 90 19 33"
```

Setiap angka itu adalah ciphertext untuk masing-masing karakter.

### Penting untuk presentasi
Saat demo, jelaskan bahwa:
- diagnosis asli tidak disimpan dalam database,
- yang disimpan justru hasil enkripsi,
- ID, nama, umur tetap terlihat,
- diagnosis baru bisa dibuka lagi jika punya private key.

---

## 4. Fungsi `encrypt_rows(plaintext, public_key)`

```python
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
```

### Penjelasan
Fungsi ini sama prinsipnya dengan `encrypt_field()`, tetapi bentuk hasilnya lebih rapi untuk ditampilkan di web atau tabel demo.

Setiap item dalam list berisi:
- `char`: karakter asli
- `ascii`: kode ASCII
- `cipher`: hasil ciphertext
- `steps`: langkah perhitungan modular exponentiation

### Kenapa dibuat terpisah?
Karena untuk tampilan antarmuka web kita butuh data yang lebih terstruktur,
jadi mudah ditampilkan sebagai tabel:

```python
[
  {"char": "I", "ascii": 73, "cipher": 82, "steps": [...]},
  {"char": "n", "ascii": 110, "cipher": 23, "steps": [...]},
  ...
]
```

### Demo yang cocok
Saat presentasi, tunjukkan bahwa satu diagnosis yang asalnya teks berubah menjadi beberapa angka cipher per karakter.

---

## 5. Fungsi `insert_patient(db, patient_id, nama, umur, diagnosis, public_key, log)`

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

### Penjelasan
Fungsi ini adalah tempat semua validasi dan proses penyimpanan pasien digabung menjadi satu.

Validasi yang dilakukan:
- ID tidak boleh duplikat
- ID harus positif
- Nama tidak boleh kosong
- Umur harus positif
- Diagnosis tidak boleh kosong

Setelah validasi lolos, maka:
1. diagnosis dienkripsi dengan `encrypt_field()`
2. hasil cipher disimpan ke field `diagnosis`
3. record pasien ditambahkan ke list `db`

### Struktur record pasien
```python
{
  "id": 1,
  "nama": "Budi",
  "umur": 25,
  "diagnosis": "82 23 40 71 54 90 19 33"
}
```

### Contoh demo
```python
db = []
public_key = (5, 143)
insert_patient(db, 1, "Budi", 25, "Influenza", public_key)
print(db)
```

Outputnya akan tampak seperti:

```python
[{'id': 1, 'nama': 'Budi', 'umur': 25, 'diagnosis': '82 23 40 71 54 90 19 33'}]
```

Pada tahap ini, diagnosis sudah berubah menjadi ciphertext. Artinya, database menyimpan data yang aman untuk ditampilkan di demo.

---

## 6. Fungsi `print_database(db)`

```python
def print_database(db: list[dict]) -> None:
    print("=" * 72, "\nDATABASE EHR (Diagnosis disimpan sebagai ciphertext)\n" + "=" * 72)
    print(f"{'ID':<6}{'Nama':<24}{'Umur':<8}Diagnosis (ciphertext)")
    print("-" * 72)
    for row in db:
        print(f"{row['id']:<6}{row['nama']:<24}{row['umur']:<8}{row['diagnosis']}")
    print("=" * 72)
```

### Penjelasan
Fungsi ini menampilkan isi database secara rapi ke terminal.

Yang ditampilkan:
- `ID` pasien
- `Nama`
- `Umur`
- `Diagnosis` dalam bentuk ciphertext

### Tujuan
Tujuannya adalah untuk menunjukkan bahwa diagnosis memang tidak disimpan dalam bentuk teks asli, melainkan dalam bentuk angka encrypted.

### Contoh tampilan database
```text
====================================================================
DATABASE EHR (Diagnosis disimpan sebagai ciphertext)
====================================================================
ID    Nama                     Umur    Diagnosis (ciphertext)
--------------------------------------------------------------------
1     Budi                     25      82 23 40 71 54 90 19 33
====================================================================
```

Dari tampilan ini, jelas terlihat:
- ID masih terbaca
- nama masih terbaca
- umur masih terbaca
- diagnosis sudah terenkripsi

---

## 7. Alur kerja bagian anggota 2

### Alur lengkapnya adalah:

```text
Input diagnosis plaintext
      ↓
Konversi karakter ke ASCII
      ↓
Encrypt tiap ASCII dengan public key
      ↓
Simpan hasil ciphertext pada field diagnosis
      ↓
Tampilkan database dengan diagnosis terenkripsi
```

Contoh lengkap:

```python
public_key, private_key, detail = generate_keys()

db = []
insert_patient(db, 1, "Budi", 25, "Influenza", public_key)
print_database(db)
```

### Hasil yang ditunjukkan saat demo
- Diagnosis asli: `Influenza`
- Diagnosis di database: `82 23 40 ...`
- Artinya enkripsi berhasil terjadi sebelum data masuk ke database.

---

## 8. Kalimat penjelasan yang bisa dipakai saat presentasi

> "Bagian anggota 2 fokus pada proses enkripsi diagnosis dan penyimpanan data pasien. Pertama, diagnosis diubah menjadi kode ASCII. Setelah itu, tiap angka ASCII dienkripsi dengan public key sesuai rumus RSA `c = m^e mod n`. Hasil enkripsi ini disimpan ke database sebagai ciphertext, sedangkan ID, nama, dan umur tetap disimpan dalam bentuk plaintext. Dengan cara ini, database hanya menampilkan diagnosis yang sudah terenkripsi, bukan teks aslinya."

---

## 9. Kesimpulan
Bagian anggota 2 adalah inti dari proses keamanan data pasien pada simulasi EHR. Fungsi-fungsi ini bekerja bersama untuk:
- mengubah diagnosis menjadi angka,
- mengenkripsi diagnosis dengan public key,
- menyimpan ciphertext ke database,
- menampilkan database dengan diagnosis terproteksi.

Dengan begitu, proses enkripsi sudah selesai sebelum data pasien disimpan dan siap untuk didekripsi nanti oleh pihak yang berhak.
