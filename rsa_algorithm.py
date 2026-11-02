"""RSA maths using standard ASCII codes (printable range 32-126) as the plaintext numbers."""
import random

MIN_CHAR, MAX_CHAR, MAX_ASCII = 32, 126, 127   # printable ASCII; table limit 127


class RSAError(ValueError):
    pass


# ---------- number theory ----------
def mod_pow(base, exp, mod):
    """Square-and-multiply modular exponentiation."""
    result, base = 1, base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """Return (g, x, y) with a*x + b*y = g."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def mod_inverse(e, phi):
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise RSAError("e has no modular inverse modulo phi(n).")
    return x % phi


def is_prime(n, rounds=20):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for sp in small:
        if n == sp:
            return True
        if n % sp == 0:
            return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    bases = small if n < 3_317_044_064_679_887_385_961_981 else random.sample(range(2, n - 1), rounds)
    for a in bases:
        x = mod_pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def totient(p, q):
    """Euler's totient for n = p*q (p, q prime)."""
    return (p - 1) * (q - 1)


def choose_e(phi):
    if 1 < 17 < phi and gcd(17, phi) == 1:
        return 17
    for e in range(3, phi):
        if gcd(e, phi) == 1:
            return e
    raise RSAError("No valid public exponent e exists for these primes.")


def random_prime(lo=50, hi=400):
    while True:
        c = random.randint(lo, hi)
        if is_prime(c):
            return c


# ---------- keys ----------
def parse_prime(value, name):
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise RSAError(f"{name} must be a whole number.")
    if not is_prime(v):
        raise RSAError(f"{name} = {v} is not prime (Miller-Rabin test failed).")
    return v


def validate_e(e, phi):
    """Check a user-supplied public exponent and explain any failure."""
    if isinstance(e, str):
        e = e.strip()
    try:
        e = int(e)
    except (TypeError, ValueError):
        raise RSAError("e must be a whole number.")
    if e <= 1:
        raise RSAError(f"e = {e} is invalid: e must be greater than 1.")
    if e >= phi:
        raise RSAError(f"e = {e} is invalid: e must be smaller than \u03c6(n) = {phi}. "
                       "Choose a smaller e or larger primes.")
    g = gcd(e, phi)
    if g != 1:
        raise RSAError(f"e = {e} is invalid: gcd(e, \u03c6(n)) = gcd({e}, {phi}) = {g}, but it must be 1. "
                       f"e shares the factor {g} with \u03c6(n), so no private key d exists.")
    return e


def generate_keys(p, q, e=None):
    p, q = parse_prime(p, "p"), parse_prime(q, "q")
    if p == q:
        raise RSAError("p and q must be distinct primes.")
    n, phi = p * q, totient(p, q)
    if n <= MAX_ASCII:
        raise RSAError(f"n = {n} is too small. n must be greater than {MAX_ASCII} so every ASCII code (0-{MAX_ASCII}) can be encrypted.")
    auto = e is None or str(e).strip() == ""
    e = choose_e(phi) if auto else validate_e(e, phi)
    d = mod_inverse(e, phi)
    return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d, "e_auto": auto,
            "public_key": [e, n], "private_key": [d, n],
            "check": f"({d} x {e}) mod {phi} = {(d * e) % phi}"}


# ---------- ASCII mapping ----------
def char_to_num(ch):
    return ord(ch)


def num_to_char(n):
    return chr(n)


def validate_text(text):
    if not text:
        raise RSAError("Please enter a plaintext message.")
    for ch in text:
        if not (MIN_CHAR <= ord(ch) <= MAX_CHAR):
            raise RSAError(f"Unsupported character '{ch}'. Use printable ASCII only (codes {MIN_CHAR}-{MAX_CHAR}).")
    return text


def text_to_numbers(text):
    return [char_to_num(c) for c in text]


def numbers_to_text(nums):
    return "".join(num_to_char(m) for m in nums)


# ---------- encrypt / decrypt ----------
def encrypt_message(p, q, plaintext, e=None):
    keys = generate_keys(p, q, e)
    text = validate_text(plaintext)
    nums = text_to_numbers(text)
    e, n = keys["e"], keys["n"]
    cipher = [mod_pow(m, e, n) for m in nums]
    steps = [{"char": ch, "m": m, "formula": f"{m}^{e} mod {n}", "c": c}
             for ch, m, c in zip(text, nums, cipher)]
    return {"keys": keys, "plaintext": text, "numbers": nums, "cipher": cipher, "steps": steps}


def decrypt_message(p, q, cipher, e=None):
    keys = generate_keys(p, q, e)
    try:
        cipher = [int(c) for c in cipher]
    except (TypeError, ValueError):
        raise RSAError("Encrypted values must be integers.")
    if not cipher:
        raise RSAError("Nothing to decrypt. Encrypt a message first.")
    d, n = keys["d"], keys["n"]
    nums = [mod_pow(c, d, n) for c in cipher]
    if any(not (MIN_CHAR <= m <= MAX_CHAR) for m in nums):
        raise RSAError("Decryption produced a non-printable ASCII code. Wrong key or corrupted ciphertext.")
    steps = [{"c": c, "formula": f"{c}^{d} mod {n}", "m": m, "char": num_to_char(m)} for c, m in zip(cipher, nums)]
    return {"keys": keys, "numbers": nums, "plaintext": numbers_to_text(nums), "steps": steps}
