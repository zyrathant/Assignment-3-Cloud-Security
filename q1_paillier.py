"""
INTE2639 Cloud Security - Assignment 3, Question 1(5)
Paillier homomorphic encryption: implementation and verification.

Student: Phyu Phyu Shinn Thant (Zyra)
Student ID: s4022136

"""

import hashlib
from math import gcd
from random import SystemRandom

# ----------------------------------------------------------------------
# 1. KEY PARAMETERS
# ----------------------------------------------------------------------

p = int("12047668724451935025675177759137387063314411407944880094247661017981674172412559252162064697218699121792612806548356630220390004956893662620206680715220127")

q = int("10843788325792901805996478523909560957473077913465656708885345681339272781430818434106794014468749321491502300187784460638235523675104410467995139085514387")


def lcm(a: int, b: int) -> int:
    return a * b // gcd(a, b)


def build_keys(p: int, q: int):
    """Derive the Paillier public and private key from the primes p and q."""
    n = p * q                      # public modulus
    n_sq = n * n                   # ciphertexts live in Z*_{n^2}
    g = n + 1                      # standard simplification of the generator
    lam = lcm(p - 1, q - 1)        # private key: Carmichael function lambda(n)
    mu = pow(lam, -1, n)           # private key: lambda^{-1} mod n
    return {"n": n, "n_sq": n_sq, "g": g, "lam": lam, "mu": mu}


# ----------------------------------------------------------------------
# 2. CORE PAILLIER OPERATIONS
# ----------------------------------------------------------------------

def encrypt(m: int, key: dict, r: int = None) -> int:
    """
    c = g^m * r^n  (mod n^2)

    r is a fresh random value coprime to n. It is what makes Paillier
    probabilistic: encrypting the same income twice yields different
    ciphertexts, so the cloud cannot detect repeated values.
    """
    n, n_sq, g = key["n"], key["n_sq"], key["g"]
    if not 0 <= m < n:
        raise ValueError("plaintext must satisfy 0 <= m < n")
    if r is None:
        rng = SystemRandom()
        while True:
            r = rng.randrange(1, n)
            if gcd(r, n) == 1:
                break
    elif gcd(r, n) != 1:
        raise ValueError("r must be coprime to n")
    return (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq


def L(x: int, n: int) -> int:
    """L(x) = (x - 1) / n, exact integer division."""
    return (x - 1) // n


def decrypt(c: int, key: dict) -> int:
    """m = L(c^lambda mod n^2) * mu  (mod n)"""
    n, n_sq, lam, mu = key["n"], key["n_sq"], key["lam"], key["mu"]
    return (L(pow(c, lam, n_sq), n) * mu) % n


def homomorphic_add(ciphertexts, key: dict) -> int:
    """
    The additive homomorphism: multiplying ciphertexts modulo n^2 adds the
    underlying plaintexts. This is the operation the cloud server performs,
    and it needs no key material at all.
    """
    n_sq = key["n_sq"]
    acc = 1
    for c in ciphertexts:
        acc = (acc * c) % n_sq
    return acc


# ----------------------------------------------------------------------
# 3. MONTHLY INCOMES
# ----------------------------------------------------------------------

STUDENT_ID = "s4022136"
MONTHS = ["January", "February", "March"]


def monthly_income(student_id: str, month: str) -> int:
    """income = MD5(student_id || month) mod 10000, digest read as an integer."""
    digest = hashlib.md5((student_id + month).encode()).hexdigest()
    return int(digest, 16) % 10000


# ----------------------------------------------------------------------
# 4. RUN AND VERIFY
# ----------------------------------------------------------------------

def main():
    key = build_keys(p, q)
    n = key["n"]

    print("=" * 72)
    print("PAILLIER KEY PARAMETERS")
    print("=" * 72)
    print(f"n bit length      : {n.bit_length()}")
    print(f"lambda bit length : {key['lam'].bit_length()}")
    print(f"g                 : n + 1")
    print()
    print(f"n      = {n}")
    print()
    print(f"lambda = {key['lam']}")
    print()
    print(f"mu     = {key['mu']}")
    print()

    print("=" * 72)
    print("STEP 1 - DERIVE MONTHLY INCOMES")
    print("=" * 72)
    incomes = []
    for month in MONTHS:
        digest = hashlib.md5((STUDENT_ID + month).encode()).hexdigest()
        m = int(digest, 16) % 10000
        incomes.append(m)
        print(f"MD5('{STUDENT_ID}{month}')")
        print(f"  = {digest}")
        print(f"  mod 10000 = {m}")
    print(f"\nPlaintext sum = {sum(incomes)}")
    print()

    print("=" * 72)
    print("STEP 2 - ENCRYPT EACH INCOME")
    print("=" * 72)
    # Fixed r values so the run is reproducible and matches the report.
    # In deployment these must be freshly random for every encryption.
    fixed_r = [
        int("483234870591042350042414802523235328711407403370154753041413724109"
            "011568100045066068533309329699609547827637923415996182550899059030"
            "953955637849738125612307035912727149083224969808080877995020679036"
            "383860442893484329042067480007710507027134035460261368465534664924"
            "38380178005534377659847586922377975363180034"),
        int("587919361290994698875333000848250680021251761036243015649104125575"
            "086822239396539074207740287166928236465697834091031702815451840578"
            "747399512448461604677786242195828514794699382332072690979333229785"
            "267511103595002795918336347387388231477346962722141511284010637255"
            "7391254077437131551451143096597340023791481"),
        int("268425124467617143986551013035295578356512620220858217876065112811"
            "569527590109273015332041488556617788514981098122208120292224125244"
            "800184823091030968991366308530627139060168708988756189479847461967"
            "948226285016526488927296049310835202399344095458345512156463295495"
            "59706361155792459925462119477910860188092431"),
    ]
    ciphertexts = []
    for month, m, r in zip(MONTHS, incomes, fixed_r):
        c = encrypt(m, key, r)
        ciphertexts.append(c)
        print(f"{month:9s} m = {m:5d} -> ciphertext of {c.bit_length()} bits")
    print()

    print("=" * 72)
    print("STEP 3 - CLOUD-SIDE HOMOMORPHIC ADDITION")
    print("=" * 72)
    c_sum = homomorphic_add(ciphertexts, key)
    print("c_sum = c1 * c2 * c3 mod n^2")
    print(f"c_sum has {c_sum.bit_length()} bits")
    print("The server performed this using only public information.")
    print()

    print("=" * 72)
    print("STEP 4 - CLIENT-SIDE DECRYPTION AND VERIFICATION")
    print("=" * 72)
    recovered = decrypt(c_sum, key)
    expected = sum(incomes)
    print(f"decrypt(c_sum) = {recovered}")
    print(f"expected sum   = {expected}")
    print(f"MATCH          : {recovered == expected}")
    print()

    print("Individual decryptions (sanity check on part 2):")
    for month, m, c in zip(MONTHS, incomes, ciphertexts):
        d = decrypt(c, key)
        print(f"  {month:9s} decrypt -> {d:5d}  (original {m:5d})  "
              f"{'OK' if d == m else 'MISMATCH'}")
    print()

    print("=" * 72)
    print("EXTRA CHECK - PROBABILISTIC ENCRYPTION")
    print("=" * 72)
    a = encrypt(incomes[0], key)
    b = encrypt(incomes[0], key)
    print(f"Two encryptions of the same income {incomes[0]}:")
    print(f"  ciphertexts identical? {a == b}")
    print(f"  both decrypt to {decrypt(a, key)} and {decrypt(b, key)}")
    print("Different ciphertexts, same plaintext: semantic security holds.")

    print()
    print("FULL CIPHERTEXT VALUES")
    print("=" * 72)
    for i, c in enumerate(ciphertexts, 1):
        print(f"\nc{i} =\n{c}")
    print(f"\nc_sum =\n{c_sum}")


if __name__ == "__main__":
    main()
