# Penjelasan Anggota 3: Dekripsi, CLI, Integrasi, dan Pengujian

Dokumen ini dibuat untuk membantu demo presentasi kelompok. Fokus bagian ini adalah bagaimana ciphertext dikembalikan menjadi diagnosis asli, lalu diintegrasikan dalam alur program CLI dan sistem yang dijalankan secara utuh.

---

## 1. Tujuan bagian

Anggota 3 bertanggung jawab pada:
- dekripsi ciphertext menjadi diagnosis asli,
- validasi input pengguna,
- menjalankan menu CLI,
- menghubungkan semua komponen sebelumnya menjadi satu program yang bisa dijalankan.

Jadi, anggota 3 adalah penghubung antara bagian hasil kerja anggota 1 dan 2 menjadi alur lengkap.

---

## 2. Fungsi `_parse_ciphertext(ciphertext_str, n)`

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

### Penjelasan
Fungsi ini memecah ciphertext yang berbentuk string angka dipisahkan spasi dan memastikan formatnya valid.

Contoh:
```python
ciphertext = "82 23 40 71"
```

akan diubah menjadi:
```python
[82, 23, 40, 71]
```

### Kenapa penting?
Karena ciphertext tidak boleh sembarang string. Harus berupa angka yang masuk ke rentang `0 <= c < n`.

---

## 3. Fungsi `decrypt_field(ciphertext_str, private_key, log)`

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

### Penjelasan
Fungsi ini menerapkan dekripsi RSA untuk setiap angka ciphertext.

Rumusnya:

```text
m = c^d mod n
```

Setelah hasilnya didapat, angka itu diubah kembali menjadi karakter ASCII dengan `chr(value)`.

Misalnya:
- `value = 73` → `chr(73)` = `I`
- `value = 110` → `chr(110)` = `n`

### Tujuan
Fungsi ini adalah kebalikan dari bagian anggota 2. Jika di anggota 2 diagnosis diubah menjadi ciphertext, maka di sini ciphertext dikembalikan ke teks asli.

---

## 4. Fungsi `decrypt_rows(ciphertext_str, private_key, reveal)`

```python
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
```

### Penjelasan
Fungsi ini mirip dengan `decrypt_field()`, tetapi bentuk hasilnya dibuat lebih terstruktur untuk web.

Isi tiap item:
- `cipher`: angka ciphertext
- `m`: hasil dekripsi numerik
- `char`: karakter hasil dekripsi
- `steps`: langkah-langkah proses

### Fungsi `reveal`
- `reveal = True` → menampilkan langkah detail
- `reveal = False` → menyembunyikan detail yang bisa membocorkan `d`

Ini berguna untuk keamanan demo dan memisahkan peran akses di web.

---

## 5. Fungsi `_positive_int(prompt)`

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

### Penjelasan
Fungsi ini membaca input dari pengguna dan memastikan input tersebut:
- berupa angka bulat
- bernilai positif
- bukan nol ataupun negatif

Contoh:
- `1` → valid
- `0` → error
- `abc` → error

### Penting untuk CLI
Karena menu CLI meminta data seperti:
- ID pasien
- umur
- pilihan menu

Semua itu harus divalidasi sebelum diproses.

---

## 6. Fungsi `run_cli()`

```python
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
```

### Penjelasan
Menu ini menyediakan alur pengguna untuk:
1. membuat key pair
2. memasukkan pasien
3. melihat database raw
4. melihat rekam medis setelah dekripsi
5. keluar dari program

### Demo yang cocok
Pada presentasi, jalankan program lalu tunjukkan:
- kunci dibuat
- pasien ditambahkan
- database menampilkan ciphertext
- diagnosis dibuka kembali dengan private key
- semua berjalan dalam satu loop CLI

---

## 7. Fungsi `main()`

```python
def main() -> None:
    parser = argparse.ArgumentParser(description="EHR RSA demo")
    parser.add_argument("--web", action="store_true", help="Jalankan versi web")
    args = parser.parse_args()
    if args.web:
        run_web()
    else:
        run_cli()
```

### Penjelasan
Fungsi ini menentukan mode program:
- `python ehr_rsa.py` → CLI
- `python ehr_rsa.py --web` → web (jika versi web dijalankan)

### Kenapa penting?
Karena program bisa dijalankan dalam dua cara yang berbeda, tetapi tetap memakai fungsi yang sama. Ini menunjukkan integrasi dan kesinambungan alur kerja.

---

## 8. Alur integrasi secara utuh

Semua bagian bekerja dalam satu siklus:

```text
Generate key pair
      ↓
Input data pasien
      ↓
Diagnosis plaintext → ASCII → enkripsi
      ↓
Simpan ciphertext ke database
      ↓
Ambil ciphertext → dekripsi
      ↓
Diagnosis plaintext muncul kembali
```

### Hubungan antarbagiannya:
- Anggota 1: menghasilkan key pair
- Anggota 2: mengenkripsi diagnosis dan menyimpannya
- Anggota 3: membuka diagnosis kembali dan menghubungkan program

---

## 9. Uji coba yang perlu ditunjukkan saat demo

Anggota 3 harus menampilkan hasil pengujian seperti:
- ID duplikat
- umur tidak valid
- diagnosis kosong
- ciphertext tidak valid
- menjalankan dekripsi sebelum key pair dibuat

Contoh:
```python
# ID duplikat
insert_patient(db, 1, "Budi", 25, "Influenza", public_key)
insert_patient(db, 1, "Andi", 30, "Demam", public_key)
```

Error yang muncul:
```text
ValueError: ID pasien sudah digunakan.
```

---

## 10. Kalimat presentasi yang bisa dipakai

> "Bagian anggota 3 fokus pada dekripsi, validasi input, dan penggabungan seluruh alur program. Setelah anggota 2 menyimpan diagnosis dalam bentuk ciphertext, anggota 3 mengambil data tersebut, melakukan parsing, lalu mendekripsinya dengan private key. Setelah itu, angka ASCII kembali diubah menjadi karakter, sehingga diagnosis asli muncul lagi. Selain itu, kami juga menyiapkan menu CLI dan pengecekan error agar program lebih robust dan siap dipresentasikan."

---

## 11. Kesimpulan

Anggota 3 memastikan seluruh sistem RSA pada proyek ini berjalan sebagai satu kesatuan yang utuh. Tanpa bagian ini, kunci yang dibuat oleh anggota 1 dan ciphertext yang dibuat oleh anggota 2 tidak akan bisa dipakai secara fungsional dalam program. Jadi anggota 3 adalah bagian yang mengintegrasikan semua fungsi menjadi alur kerja lengkap, dari input sampai output.
