# Penjelasan Anggota 1: Pembangkitan Kunci RSA dan Matematika Dasar

Dokumen ini dibuat untuk membantu demo presentasi kelompok. Fokus bagian ini adalah bagaimana kunci publik dan kunci privat dibuat dalam RSA.

---

## 1. Tujuan bagian

Anggota 1 bertanggung jawab pada proses pembangkitan pasangan kunci RSA yang akan dipakai oleh anggota 2 dan 3.

Kunci RSA terdiri dari:
- kunci publik: `(e, n)`
- kunci privat: `(d, n)`

Kunci ini dibentuk dari dua bilangan prima besar `p` dan `q`.

---

## 2. Fungsi `gcd(a, b)`

```python
def gcd(a: int, b: int) -> int:
    """Return the greatest common divisor using Euclid's algorithm."""
    while b:
        a, b = b, a % b
    return abs(a)
```

### Penjelasan
Fungsi ini mencari FPB (greatest common divisor) dari dua bilangan menggunakan algoritma Euclid.

Contoh:
```python
gcd(12, 18)
```
Hasilnya:
```python
6
```

### Kenapa penting?
Dalam RSA, kita harus memastikan:

```text
gcd(e, phi(n)) = 1
```

Artinya `e` dan `phi(n)` harus saling prima. Jika tidak, maka invers modular tidak ada dan kunci tidak valid.

---

## 3. Fungsi `is_prime(n)`

```python
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
```

### Penjelasan
Fungsi ini mengecek apakah suatu bilangan merupakan bilangan prima.

Contoh:
```python
is_prime(7)   # True
is_prime(10)  # False
```

### Kenapa penting?
RSA memakai dua bilangan prima `p` dan `q` untuk menghitung `n`.

---

## 4. Fungsi `generate_prime(min_val, max_val)`

```python
def generate_prime(min_val: int = 257, max_val: int = 997) -> int:
    """Choose a prime from an inclusive range."""
    if min_val > max_val:
        raise ValueError("Batas minimum harus <= batas maksimum.")
    candidates = [n for n in range(min_val, max_val + 1) if is_prime(n)]
    if not candidates:
        raise ValueError("Rentang tidak memuat bilangan prima.")
    return _RNG.choice(candidates)
```

### Penjelasan
Fungsi ini memilih bilangan prima secara acak dari rentang tertentu.

Pada program ini, `p` dan `q` dipilih dengan cara acak agar tiap run menghasilkan key pair yang berbeda.

---

## 5. Fungsi `mod_inverse(e, phi)`

```python
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
```

### Penjelasan
Fungsi ini mencari invers modular `d` dari `e` terhadap `phi(n)`, sehingga:

```text
(e × d) mod phi(n) = 1
```

Ini adalah inti dari RSA: kunci publik `(e, n)` dan kunci privat `(d, n)` dibuat agar proses dekripsi bisa membalik proses enkripsi.

### Contoh demo
Kalau:
- `e = 7`
- `phi(n) = 40`

Maka `d` bisa dihitung sedemikian rupa supaya:

```text
7 × d mod 40 = 1
```

Nilai `d` yang memenuhi adalah `23`.

---

## 6. Fungsi `generate_keys()`

```python
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
```

### Penjelasan
Fungsi ini menghasilkan semua komponen kunci RSA.

Langkahnya:
1. Pilih `p` dan `q` prima berbeda
2. Hitung `n = p × q`
3. Hitung `phi(n) = (p-1)(q-1)`
4. Pilih `e` sehingga `gcd(e, phi(n)) = 1`
5. Hitung `d = e⁻¹ mod phi(n)`
6. Kembalikan:
   - public key: `(e, n)`
   - private key: `(d, n)`

### Contoh sederhana
Misalkan:
- `p = 11`
- `q = 13`
- `n = 143`
- `phi(n) = (11-1)(13-1) = 120`
- pilih `e = 7`, karena `gcd(7,120)=1`
- lalu `d = 103`, karena `7 × 103 mod 120 = 1`

Maka:
- public key = `(7, 143)`
- private key = `(103, 143)`

---

## 7. Fungsi `extended_euclid_log(a, b)`

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
```

### Penjelasan
Fungsi ini membuat log langkah yang digunakan pada Extended Euclidean Algorithm.

Tujuannya adalah supaya saat demo, kita bisa menunjukkan bagaimana `d` dihitung secara manual dan mudah dibaca.

---

## 8. Fungsi `key_generation_log(detail)`

```python
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
```

### Penjelasan
Fungsi ini menyusun log lengkap untuk demo.

Ini berguna saat presentasi karena kita bisa menampilkan langkah-langkah perhitungan dengan jelas:
- nilai `p`, `q`
- nilai `n`
- nilai `phi(n)`
- proses Extended Euclidean
- hasil `d`
- public key dan private key

---

## 9. Rumus RSA yang harus dijelaskan

Bagian ini yang paling penting untuk presentasi.

### Langkah-langkah pembangkitan kunci:
1. Pilih dua bilangan prima berbeda: `p` dan `q`
2. Hitung `n = p × q`
3. Hitung `phi(n) = (p-1)(q-1)`
4. Pilih `e` dengan syarat `gcd(e, phi(n)) = 1`
5. Hitung `d` sehingga `(e × d) mod phi(n) = 1`

### Hubungan antara kunci:
- Public key: `(e, n)`
- Private key: `(d, n)`

### Rumus dasar RSA:
- Enkripsi: `c = m^e mod n`
- Dekripsi: `m = c^d mod n`

---

## 10. Kalimat presentasi yang bisa dipakai

> "Bagian anggota 1 bertanggung jawab pada pembangkitan kunci RSA. Kita memilih dua bilangan prima `p` dan `q`, lalu menghitung `n = p × q` dan `phi(n) = (p-1)(q-1)`. Setelah itu, dipilih `e` yang relatif prima dengan `phi(n)`, lalu dihitung `d` sebagai invers modular dari `e` terhadap `phi(n)`. Hasilnya adalah public key `(e, n)` dan private key `(d, n)`. Kunci ini kemudian dipakai oleh anggota 2 untuk enkripsi diagnosis dan anggota 3 untuk dekripsi kembali."

---

## 11. Kesimpulan

Bagian anggota 1 adalah pondasi dari seluruh sistem RSA. Tanpa kunci yang valid, enkripsi dan dekripsi tidak bisa terjadi. Fungsi-fungsi ini memastikan bahwa:
- kunci dibuat dengan benar
- `e` dan `phi(n)` saling prima
- `d` adalah invers modular yang sesuai
- public key dan private key dapat dipakai untuk operasi RSA yang benar.
