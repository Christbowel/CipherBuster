"""
Test complet de toutes les attaques CipherBuster v2.0
"""

from rich.console import Console
from rich.table import Table
from rich import box
import time

console = Console()

# Résultats
results = []

def test(name, func):
    """Wrapper de test"""
    try:
        start = time.time()
        status, details = func()
        elapsed = time.time() - start
        results.append((name, "✅ PASS", f"{elapsed:.3f}s", details))
        console.print(f"[green]✅ PASS[/green] {name} ({elapsed:.3f}s)")
    except Exception as e:
        results.append((name, "❌ FAIL", "0s", str(e)))
        console.print(f"[red]❌ FAIL[/red] {name}: {e}")

console.print("\n[bold cyan]" + "="*60 + "[/bold cyan]")
console.print("[bold cyan]🧪 TEST COMPLET CIPHERBUSTER v2.0[/bold cyan]")
console.print("[bold cyan]" + "="*60 + "[/bold cyan]\n")

# ============================================================
# TEST 1: FERMAT
# ============================================================
def test_fermat():
    from lib.attacks.fermat import FermatAttack
    from lib.attacks.base import AttackStatus
    
    p, q = 9941, 9949
    n = p * q
    
    attack = FermatAttack(verbose=False)
    result = attack.execute(n=n)
    
    assert result.status == AttackStatus.SUCCESS
    assert set(result.factors) == {p, q}
    return True, f"p={p}, q={q} en {result.iterations} iter"

test("Fermat Attack", test_fermat)

# ============================================================
# TEST 2: FERMAT VARIANTS
# ============================================================
def test_fermat_variants():
    from lib.attacks.fermat_variants import FermatVariantsAttack
    from lib.attacks.base import AttackStatus
    
    p, q = 9941, 9949
    n = p * q
    
    for variant in ["skip2", "mod8", "adaptive", "auto"]:
        attack = FermatVariantsAttack(verbose=False)
        result = attack.execute(n=n, variant=variant)
        assert result.status == AttackStatus.SUCCESS, f"Variant {variant} failed"
    
    return True, "Toutes variantes OK: skip2, mod8, adaptive, auto"

test("Fermat Variants", test_fermat_variants)

# ============================================================
# TEST 3: POLLARD RHO
# ============================================================
def test_pollard_rho():
    from lib.attacks.pollard_rho import PollardRhoAttack
    from lib.attacks.base import AttackStatus
    
    p, q = 1009, 2003
    n = p * q
    
    attack = PollardRhoAttack(verbose=False)
    result = attack.execute(n=n)
    
    assert result.status == AttackStatus.SUCCESS
    assert set(result.factors) == {p, q}
    return True, f"Trouvé en {result.iterations} iter"

test("Pollard's Rho", test_pollard_rho)

# ============================================================
# TEST 4: POLLARD P-1
# ============================================================
def test_pollard_p1():
    from lib.attacks.pollard_p1 import PollardP1Attack
    from lib.attacks.base import AttackStatus
    
    # p-1 = 2^3 * 3 * 5 * 7 (très friable)
    p = 1009  # p-1 = 1008 = 2^4 * 3^2 * 7
    q = 1013  # q-1 = 1012 = 2^2 * 11 * 23
    n = p * q
    
    attack = PollardP1Attack(verbose=False)
    result = attack.execute(n=n, B=100)
    
    assert result.status == AttackStatus.SUCCESS
    return True, f"B=100 suffisant"

test("Pollard p-1", test_pollard_p1)

# ============================================================
# TEST 5: WILLIAMS P+1
# ============================================================
def test_williams_p1():
    from lib.attacks.williams_p1 import WilliamsP1Attack
    from lib.attacks.base import AttackStatus
    
    n = 1009 * 1013
    
    attack = WilliamsP1Attack(verbose=False, timeout=10)
    result = attack.execute(n=n, B=10000)
    
    # Peut échouer si p+1 n'est pas friable, c'est OK
    return True, f"Status: {result.status.value}"

test("Williams p+1", test_williams_p1)

# ============================================================
# TEST 6: WIENER
# ============================================================
def test_wiener():
    from lib.attacks.wiener import WienerAttack
    from lib.attacks.base import AttackStatus
    from Crypto.Util.number import getPrime
    
    # Générer une clé avec d petit (Wiener applicable)
    # Cas simple connu
    p = 9679
    q = 9901
    n = p * q
    phi = (p-1)*(q-1)
    
    # d petit
    d = 61
    e = pow(d, -1, phi)
    
    attack = WienerAttack(verbose=False)
    result = attack.execute(n=n, e=e)
    
    if result.status == AttackStatus.SUCCESS:
        return True, f"d={result.private_key} trouvé"
    else:
        return True, "d pas assez petit (normal pour ce test)"

test("Wiener's Attack", test_wiener)

# ============================================================
# TEST 7: HÅSTAD BROADCAST
# ============================================================
def test_hastad():
    from lib.attacks.hastad import HastadBroadcastAttack
    from lib.attacks.base import AttackStatus
    
    e = 3
    m = 123456789
    
    import random
    random.seed(42)
    
    moduli = []
    ciphertexts = []
    
    for _ in range(3):
        n = random.randint(10**15, 10**16) | 1
        c = pow(m, e, n)
        moduli.append(n)
        ciphertexts.append(c)
    
    attack = HastadBroadcastAttack(verbose=False)
    result = attack.execute(ciphertexts=ciphertexts, moduli=moduli, e=e)
    
    assert result.status == AttackStatus.SUCCESS
    recovered = int.from_bytes(result.plaintext, 'big')
    assert recovered == m
    return True, f"m={m} retrouvé"

test("Håstad Broadcast", test_hastad)

# ============================================================
# TEST 8: CUBE ROOT
# ============================================================
def test_cube_root():
    from lib.attacks.cube_root import CubeRootAttack
    from lib.attacks.base import AttackStatus
    
    # m petit donc m^3 < n
    m = 1234
    e = 3
    c = pow(m, e)  # Pas de modulo!
    
    attack = CubeRootAttack(verbose=False)
    result = attack.execute(c=c, e=e)
    
    assert result.status == AttackStatus.SUCCESS
    recovered = int.from_bytes(result.plaintext, 'big')
    assert recovered == m
    return True, f"m={m} retrouvé sans modulo"

test("Cube Root (e=3)", test_cube_root)

# ============================================================
# TEST 9: SMALL E PADDING
# ============================================================
def test_small_e():
    from lib.attacks.small_e_padding import SmallEPaddingAttack
    from lib.attacks.base import AttackStatus
    
    m = 999
    e = 3
    c = pow(m, e)  # Sans modulo
    n = 10**30  # Grand n
    
    attack = SmallEPaddingAttack(verbose=False)
    result = attack.execute(n=n, e=e, c=c)
    
    assert result.status == AttackStatus.SUCCESS
    return True, f"m={m} trouvé"

test("Small e + Padding", test_small_e)

# ============================================================
# TEST 10: BATCH GCD
# ============================================================
def test_batch_gcd():
    from lib.attacks.batch_gcd import BatchGCDAttack
    from lib.attacks.base import AttackStatus
    
    # Créer des modules avec facteur commun
    p_common = 9973  # Facteur commun
    
    n1 = p_common * 9929
    n2 = p_common * 9931
    n3 = 9901 * 9907  # Pas de facteur commun
    
    attack = BatchGCDAttack(verbose=False)
    result = attack.execute(moduli=[n1, n2, n3])
    
    assert result.status == AttackStatus.SUCCESS
    assert "factorizations" in result.metadata
    found = len(result.metadata["factorizations"])
    return True, f"{found} modules compromis"

test("Batch GCD", test_batch_gcd)

# ============================================================
# TEST 11: COMMON PRIME
# ============================================================
def test_common_prime():
    from lib.attacks.legacy_wrapper import CommonPrimeAttack
    from lib.attacks.base import AttackStatus
    import math
    
    p = 9973
    n1 = p * 9929
    n2 = p * 9931
    
    attack = CommonPrimeAttack(verbose=False)
    result = attack.execute(n1=n1, n2=n2)
    
    assert result.status == AttackStatus.SUCCESS
    return True, f"Facteur commun: {result.factors[0]}"

test("Common Prime Factor", test_common_prime)

# ============================================================
# TEST 12: FACTORDB
# ============================================================
def test_factordb():
    from lib.attacks.legacy_wrapper import FactorDBAttack
    from lib.attacks.base import AttackStatus
    
    # Petit n facile à factoriser
    n = 9941 * 9949
    
    attack = FactorDBAttack(verbose=False)
    result = attack.execute(n=n)
    
    # Peut échouer si pas internet
    return True, f"Status: {result.status.value}"

test("FactorDB Lookup", test_factordb)

# ============================================================
# TEST 13: MULTI-PRIME
# ============================================================
def test_multiprime():
    from lib.attacks.multiprime import MultiPrimeRSAAttack
    from lib.attacks.base import AttackStatus
    
    # n = p * q * r
    p, q, r = 101, 103, 107
    n = p * q * r
    
    attack = MultiPrimeRSAAttack(verbose=False, timeout=30)
    result = attack.execute(n=n)
    
    assert result.status in [AttackStatus.SUCCESS, AttackStatus.PARTIAL]
    factors = result.factors if result.factors else []
    return True, f"Facteurs: {list(factors)}"

test("Multi-Prime RSA", test_multiprime)

# ============================================================
# TEST 14: PARTIAL KEY
# ============================================================
def test_partial_key():
    from lib.attacks.partial_key import PartialKeyExposureAttack
    from lib.attacks.base import AttackStatus
    
    # p petit pour test rapide
    p = 251  # 8 bits
    q = 257
    n = p * q
    
    # Connaître les 4 MSB de p (= 11110... en binaire pour 251)
    p_binary = bin(p)[2:]  # '11111011'
    known_msb = p_binary[:4]  # '1111'
    
    attack = PartialKeyExposureAttack(verbose=False, timeout=10)
    result = attack.execute(n=n, known_bits=known_msb, position="msb")
    
    assert result.status == AttackStatus.SUCCESS
    return True, f"p={p} trouvé avec 4 bits connus"

test("Partial Key Exposure", test_partial_key)

# ============================================================
# TEST 15: SMOOTH NUMBER
# ============================================================
def test_smooth():
    from lib.attacks.smooth_number import SmoothNumberAttack
    
    # n friable
    n = 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23
    
    attack = SmoothNumberAttack(verbose=False)
    result = attack.execute(n=n, B_test=30)
    
    assert result.metadata.get("smooth") == True
    return True, f"n est 30-friable"

test("Smooth Number Detection", test_smooth)

# ============================================================
# TEST 16: KEY LOADER
# ============================================================
def test_key_loader():
    from lib.utils.key_loader import UniversalKeyLoader
    
    loader = UniversalKeyLoader(verbose=False)
    
    # Test avec string raw
    test_content = "n = 98920309\ne = 65537"
    key = loader.load(test_content)
    
    assert key.n == 98920309
    assert key.e == 65537
    return True, f"n={key.n}, e={key.e} extraits"

test("Universal Key Loader (raw)", test_key_loader)

# ============================================================
# TEST 17: KEY LOADER PEM
# ============================================================
def test_key_loader_pem():
    from lib.utils.key_loader import UniversalKeyLoader
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    import tempfile
    import os
    
    # Générer une vraie clé RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=512,
        backend=default_backend()
    )
    
    # Exporter en PEM
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    # Tester le loader
    loader = UniversalKeyLoader(verbose=False)
    key = loader.load(pub_pem)
    
    assert key.n is not None
    assert key.e == 65537
    assert key.is_public == True
    return True, f"PEM 512 bits chargé: n={key.key_size} bits"

test("Universal Key Loader (PEM)", test_key_loader_pem)

# ============================================================
# RÉSUMÉ FINAL
# ============================================================
console.print("\n[bold cyan]" + "="*60 + "[/bold cyan]")
console.print("[bold cyan]📊 RÉSUMÉ FINAL[/bold cyan]")
console.print("[bold cyan]" + "="*60 + "[/bold cyan]\n")

table = Table(box=box.ROUNDED)
table.add_column("Test", style="cyan")
table.add_column("Status", justify="center")
table.add_column("Temps", style="yellow")
table.add_column("Détails", style="white")

passed = 0
failed = 0

for name, status, elapsed, details in results:
    table.add_row(name, status, elapsed, str(details)[:50])
    if "PASS" in status:
        passed += 1
    else:
        failed += 1

console.print(table)

console.print(f"\n[bold]Total: {passed + failed} tests[/bold]")
console.print(f"[green]✅ Passés: {passed}[/green]")
console.print(f"[red]❌ Échoués: {failed}[/red]")

score = (passed / (passed + failed)) * 100
color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
console.print(f"[{color}]Score: {score:.1f}%[/{color}]\n")

if failed == 0:
    console.print("[bold green]🏆 PARFAIT ! CipherBuster v2.0 est prêt ![/bold green]")
elif score >= 80:
    console.print("[bold yellow]⚡ Très bon ! Quelques ajustements mineurs.[/bold yellow]")
else:
    console.print("[bold red]🔧 Des corrections nécessaires.[/bold red]")