"""
CipherBuster v2.0 - Framework RSA
Author: Christbowel
"""

import gmpy2
from Crypto.Util.number import *
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt
from rich import box
from termcolor import colored
import sys

# Imports des attaques optimisées
from lib.attacks.fermat import FermatAttack
from lib.attacks.pollard_rho import PollardRhoAttack
from lib.attacks.pollard_p1 import PollardP1Attack
from lib.attacks.wiener import WienerAttack
from lib.attacks.hastad import HastadBroadcastAttack
from lib.attacks.franklin_reiter import FranklinReiterAttack
from lib.attacks.legacy_wrapper import CommonModulusAttack, CommonPrimeAttack, FactorDBAttack
from lib.attacks.base import AttackStatus



# Auto-detector
from lib.core.auto_detector import RSAAnalyzer

console = Console()


def banner():
    """Affiche le banner stylé"""
    banner_text = '''[bold cyan]
  ______      __           ___           __
 / ___(_)__  / /  ___ ____/ _ )__ _____ / /____ ____
/ /__/ / _ \/ _ \/ -_) __/ _  / // (_-</ __/ -_) __/
\___/_/ .__/_//_/\__/_/ /____/\_,_/___/\__/\__/_/    v2.0
     /_/
    [cyan]Creator:[/cyan] [green]Christbowel[/green]
    [yellow]🔥 Optimized Version - Modular Architecture[/yellow]
    '''
    console.print(Panel(banner_text, border_style="cyan"))


def show_menu():
    """Affiche le menu principal avec Rich"""
    
    table = Table(
        title="🔐 CipherBuster v2.0 - Attaques RSA",
        box=box.ROUNDED,
        show_lines=True
    )
    table.add_column("ID", style="bold cyan", justify="center", width=4)
    table.add_column("Attaque", style="bold magenta", width=28)
    table.add_column("Type", style="yellow", width=18)
    table.add_column("Status", style="green", width=14)

    attacks = [
        # Factorisation
        ("", "[bold white]── FACTORISATION ──[/bold white]", "", ""),
        ("1",  "Fermat",              "Factorisation",  "✅ OPTIMISED"),
        ("2",  "Fermat Variants",     "Factorisation",  "🆕 NEW"),
        ("3",  "Pollard's Rho",       "Factorisation",  "✅ OPTIMIZED"),
        ("4",  "Pollard's p-1",       "Factorisation",  "✅ NEW"),
        ("5",  "Williams p+1",        "Factorisation",  "🆕 NEW"),
        ("6",  "Multi-Prime RSA",     "Factorisation",  "🆕 NEW"),
        # Exposants
        ("", "[bold white]── EXPONENT ──[/bold white]", "", ""),
        ("7",  "Wiener's Attack",     "Petit Exposant", "✅ FIXED"),
        ("8",  "Håstad Broadcast",    "Petit Exposant", "🆕 NEW"),
        ("9",  "Cube Root (e=3)",     "Petit Exposant", "🆕 NEW"),
        ("10", "Small e + Padding",   "Petit Exposant", "🆕 NEW"),
        # Oracle
        ("", "[bold white]── ORACLE ──[/bold white]", "", ""),
        ("11", "LSB Oracle",          "Oracle",         "🆕 NEW"),
        # Multi-Clés
        ("", "[bold white]── MULTI-KEY ──[/bold white]", "", ""),
        ("12", "Franklin-Reiter",     "Messages Liés",  "✅ FIXED"),
        ("13", "Common Modulus",      "Multi-clés",     "✓"),
        ("14", "Common Prime Factor", "Multi-modules",  "✓"),
        ("15", "Batch GCD",           "Multi-modules",  "🆕 NEW"),
        # Avancées
        ("", "[bold white]── ADVANCED ──[/bold white]", "", ""),
        ("16", "Partial Key Exposure","Clé Partielle",  "🆕 NEW"),
        ("17", "Known Plaintext",     "Texte Clair",    "🆕 NEW"),
        ("18", "Smooth Number",       "Analyse",        "🆕 NEW"),
        # Database
        ("", "[bold white]── DATABASE ──[/bold white]", "", ""),
        ("19", "FactorDB Lookup",     "Database",       "✓"),
        # Utilitaires
        ("", "[bold white]── UTILITIES ──[/bold white]", "", ""),
        ("20", "RSA Encode/Decode",   "Utilitaire",     "✓"),
        ("21", "Key Loader",          "Utilitaire",     "🆕 NEW"),
        ("22", "Private Key Compute", "Utilitaire",     "✓"),
        # Spécial
        ("", "", "", ""),
        ("99", "🤖 AUTO-DETECT",      "Automated Analysis",   "🆕 NEW"),
        ("0",  "Exit",                "",               ""),
    ]
    
    for row in attacks:
        table.add_row(*row)
    
    console.print(table)


def attack_fermat():
    """Attaque de Fermat optimisée"""
    console.print("\n[bold magenta]🔨 FERMAT'S FACTORIZATION ATTACK[/bold magenta]")
    console.print("[green]Efficace quand p et q sont proches[/green]\n")
    
    n = IntPrompt.ask("💡 Entrez n")
    max_iter = IntPrompt.ask("🔄 Max iterations", default=1000000)
    
    console.print("\n[yellow]⚙️  Lancement de l'attaque...[/yellow]\n")
    
    attack = FermatAttack(verbose=True, timeout=300)
    result = attack.execute(n=n, max_iterations=max_iter)
    
    display_result(result)
    
    if result.status == AttackStatus.SUCCESS and result.factors:
        ask_compute_private_key(result.factors)


def attack_pollard_rho():
    """Pollard's Rho optimisé"""
    console.print("\n[bold magenta]🌀 POLLARD'S RHO ATTACK[/bold magenta]")
    console.print("[green]Algorithme Floyd (tortue et lièvre)[/green]\n")
    
    n = IntPrompt.ask("💡 Entrez n")
    
    console.print("\n[yellow]⚙️  Lancement de l'attaque...[/yellow]\n")
    
    attack = PollardRhoAttack(verbose=True, timeout=300)
    result = attack.execute(n=n)
    
    display_result(result)
    
    if result.status == AttackStatus.SUCCESS and result.factors:
        ask_compute_private_key(result.factors)


def attack_pollard_p1():
    """Pollard's p-1 optimisé"""
    console.print("\n[bold magenta]🎯 POLLARD'S p-1 ATTACK[/bold magenta]")
    console.print("[green]Fonctionne si p-1 est friable[/green]\n")
    
    n = IntPrompt.ask("💡 Entrez n")
    B = IntPrompt.ask("📊 Borne B (friabilité)", default=1000000)
    
    console.print("\n[yellow]⚙️  Lancement de l'attaque...[/yellow]\n")
    
    attack = PollardP1Attack(verbose=True, timeout=300)
    result = attack.execute(n=n, B=B)
    
    display_result(result)
    
    if result.status == AttackStatus.SUCCESS and result.factors:
        ask_compute_private_key(result.factors)


def attack_wiener():
    """Wiener's attack corrigé"""
    console.print("\n[bold magenta]🔑 WIENER'S ATTACK[/bold magenta]")
    console.print("[green]Fonctionne si d < n^0.25[/green]\n")
    
    n = IntPrompt.ask("💡 Entrez n")
    e = IntPrompt.ask("💡 Entrez e")
    
    has_cipher = Prompt.ask("❓ Avez-vous un ciphertext à déchiffrer?", choices=["y", "n"], default="n")
    c = None
    if has_cipher == "y":
        c = IntPrompt.ask("💡 Entrez c")
    
    console.print("\n[yellow]⚙️  Lancement de l'attaque...[/yellow]\n")
    
    attack = WienerAttack(verbose=True, timeout=300)
    result = attack.execute(n=n, e=e, c=c)
    
    display_result(result)


def attack_hastad():
    """Håstad Broadcast Attack - NOUVEAU"""
    console.print("\n[bold magenta]📡 HÅSTAD BROADCAST ATTACK[/bold magenta]")
    console.print("[green]Même message envoyé à plusieurs destinataires avec même e[/green]\n")
    
    e = IntPrompt.ask("💡 Exposant e commun", default=3)
    num = IntPrompt.ask(f"💡 Nombre de chiffrés (minimum {e})", default=e)
    
    if num < e:
        console.print(f"[red]❌ Vous devez avoir au moins {e} chiffrés![/red]")
        return
    
    ciphertexts = []
    moduli = []
    
    for i in range(num):
        console.print(f"\n[cyan]📝 Paire {i+1}/{num}:[/cyan]")
        c = IntPrompt.ask(f"  Ciphertext c{i+1}")
        n = IntPrompt.ask(f"  Module n{i+1}")
        ciphertexts.append(c)
        moduli.append(n)
    
    console.print("\n[yellow]⚙️  Lancement de l'attaque...[/yellow]\n")
    
    attack = HastadBroadcastAttack(verbose=True, timeout=300)
    result = attack.execute(ciphertexts=ciphertexts, moduli=moduli, e=e)
    
    display_result(result)


def attack_franklin_reiter():
    """Franklin-Reiter corrigé"""
    console.print("\n[bold magenta]🔗 FRANKLIN-REITER ATTACK[/bold magenta]")
    console.print("[green]Messages liés: M2 = a*M1 + b[/green]\n")
    
    n = IntPrompt.ask("💡 Entrez n")
    e = IntPrompt.ask("💡 Entrez e")
    c1 = IntPrompt.ask("💡 Premier ciphertext (C1)")
    c2 = IntPrompt.ask("💡 Deuxième ciphertext (C2)")
    
    console.print("\n[cyan]Relation linéaire: M2 = a*M1 + b[/cyan]")
    a = IntPrompt.ask("💡 Coefficient a")
    b = IntPrompt.ask("💡 Constante b")
    
    console.print("\n[yellow]⚙️  Lancement de l'attaque...[/yellow]\n")
    
    attack = FranklinReiterAttack(verbose=True, timeout=300)
    result = attack.execute(n=n, e=e, c1=c1, c2=c2, a=a, b=b)
    
    display_result(result)


def attack_common_modulus():
    """Common Modulus Attack"""
    console.print("\n[bold magenta]🔄 COMMON MODULUS ATTACK[/bold magenta]")
    console.print("[green]Même n, différents e[/green]\n")
    
    n = IntPrompt.ask("💡 Module commun n")
    e1 = IntPrompt.ask("💡 Premier exposant e1")
    e2 = IntPrompt.ask("💡 Deuxième exposant e2")
    c1 = IntPrompt.ask("💡 Premier ciphertext c1")
    c2 = IntPrompt.ask("💡 Deuxième ciphertext c2")
    
    console.print("\n[yellow]⚙️  Lancement de l'attaque...[/yellow]\n")
    
    attack = CommonModulusAttack(verbose=True)
    result = attack.execute(n=n, e1=e1, e2=e2, c1=c1, c2=c2)
    
    display_result(result)


def attack_factordb():
    """FactorDB Lookup"""
    console.print("\n[bold magenta]🌐 FACTORDB LOOKUP[/bold magenta]")
    console.print("[green]Vérification dans la base de données FactorDB[/green]\n")
    console.print("[yellow]⚠️  Connexion internet requise![/yellow]\n")
    
    n = IntPrompt.ask("💡 Entrez n")
    
    console.print("\n[yellow]⚙️  Consultation de FactorDB...[/yellow]\n")
    
    attack = FactorDBAttack(verbose=True)
    result = attack.execute(n=n)
    
    display_result(result)
    
    if result.status == AttackStatus.SUCCESS and result.factors:
        ask_compute_private_key(result.factors)


def attack_common_prime():
    """Common Prime Factor Attack"""
    console.print("\n[bold magenta]🔍 COMMON PRIME FACTOR ATTACK[/bold magenta]")
    console.print("[green]Trouve le facteur commun entre deux modules[/green]\n")
    
    n1 = IntPrompt.ask("💡 Premier module n1")
    n2 = IntPrompt.ask("💡 Deuxième module n2")
    
    console.print("\n[yellow]⚙️  Calcul du GCD...[/yellow]\n")
    
    attack = CommonPrimeAttack(verbose=True)
    result = attack.execute(n1=n1, n2=n2)
    
    display_result(result)


def rsa_encode_decode():
    """RSA Encode/Decode"""
    console.print("\n[bold magenta]🔐 RSA ENCODE/DECODE[/bold magenta]\n")
    
    choice = Prompt.ask("Choisir", choices=["encode", "decode"], default="decode")
    
    if choice == "encode":
        e = IntPrompt.ask("💡 Exposant e")
        n = IntPrompt.ask("💡 Module n")
        m = IntPrompt.ask("💡 Message m (nombre)")
        Encode(e, n, m)
    else:
        c = IntPrompt.ask("💡 Ciphertext c")
        n = IntPrompt.ask("💡 Module n")
        d = IntPrompt.ask("💡 Clé privée d")
        Decode(c, n, d)


def extract_pubkey():
    """Extract Public Key"""
    console.print("\n[bold magenta]📄 PUBLIC KEY EXTRACTION[/bold magenta]\n")
    
    filename = Prompt.ask("💡 Chemin du fichier de clé publique")
    
    try:
        n, e = extract_public_key(filename)
        console.print(f"\n[green]✓ Extraction réussie![/green]")
        console.print(f"[cyan]n = {n}[/cyan]")
        console.print(f"[cyan]e = {e}[/cyan]")
    except Exception as ex:
        console.print(f"[red]✗ Erreur: {ex}[/red]")


def compute_private_key():
    """Compute Private Key"""
    console.print("\n[bold magenta]🔑 PRIVATE KEY COMPUTATION[/bold magenta]\n")
    
    p = IntPrompt.ask("💡 Premier facteur p")
    q = IntPrompt.ask("💡 Deuxième facteur q")
    e = IntPrompt.ask("💡 Exposant e")
    
    try:
        d = PrivateKey(p, q, e)
        console.print(f"\n[green]✓ Clé privée calculée![/green]")
        console.print(f"[bold cyan]d = {d}[/bold cyan]")
    except Exception as ex:
        console.print(f"[red]✗ Erreur: {ex}[/red]")


def auto_detect():
    """Mode Auto-Detect - NOUVEAU"""
    console.print("\n[bold magenta]🤖 MODE AUTO-DETECT[/bold magenta]")
    console.print("[green]Analyse automatique et suggestions d'attaques[/green]\n")
    
    # Collecter les infos disponibles
    has_n = Prompt.ask("❓ Avez-vous n?", choices=["y", "n"], default="y")
    n = IntPrompt.ask("💡 Entrez n") if has_n == "y" else None
    
    has_e = Prompt.ask("❓ Avez-vous e?", choices=["y", "n"], default="y")
    e = IntPrompt.ask("💡 Entrez e") if has_e == "y" else None
    
    has_c = Prompt.ask("❓ Avez-vous un ciphertext?", choices=["y", "n"], default="n")
    c = IntPrompt.ask("💡 Entrez c") if has_c == "y" else None
    
    # Analyser
    analyzer = RSAAnalyzer()
    suggestions = analyzer.analyze(n=n, e=e, c=c)
    
    if suggestions:
        console.print("\n[yellow]💡 Lancer l'attaque recommandée?[/yellow]")
        launch = Prompt.ask("Choix", choices=["y", "n"], default="y")
        
        if launch == "y" and suggestions:
            # Lancer la première suggestion
            attack_name = suggestions[0][0]
            
            if attack_name == "fermat" and n:
                attack = FermatAttack(verbose=True)
                result = attack.execute(n=n)
                display_result(result)
            elif attack_name == "wiener" and n and e:
                attack = WienerAttack(verbose=True)
                result = attack.execute(n=n, e=e, c=c)
                display_result(result)
            elif attack_name == "factordb" and n:
                attack = FactorDBAttack(verbose=True)
                result = attack.execute(n=n)
                display_result(result)


def display_result(result):
    """Affiche le résultat d'une attaque de manière stylée"""
    console.print("\n" + "="*70)
    console.print("[bold cyan]📊 RÉSULTAT DE L'ATTAQUE[/bold cyan]")
    console.print("="*70 + "\n")
    
    # Status
    status_colors = {
        AttackStatus.SUCCESS: "green",
        AttackStatus.FAILED: "red",
        AttackStatus.TIMEOUT: "yellow",
        AttackStatus.PARTIAL: "blue"
    }
    color = status_colors.get(result.status, "white")
    console.print(f"Status: [{color}]{result.status.value.upper()}[/{color}]")
    console.print(f"Message: {result.message}")
    console.print(f"Temps: {result.time_elapsed:.4f}s")
    
    if result.iterations > 0:
        console.print(f"Itérations: {result.iterations}")
    
    # Résultats
    if result.factors:
        p, q = result.factors
        console.print(f"\n[bold green]✓ FACTEURS TROUVÉS:[/bold green]")
        console.print(f"  p = {p}")
        console.print(f"  q = {q}")
        console.print(f"  Vérif: p × q = {p * q}")
    
    if result.private_key:
        console.print(f"\n[bold green]✓ CLÉ PRIVÉE:[/bold green]")
        console.print(f"  d = {result.private_key}")
    
    if result.plaintext:
        console.print(f"\n[bold green]✓ PLAINTEXT:[/bold green]")
        try:
            decoded = result.plaintext.decode('utf-8', errors='ignore')
            console.print(f"  Texte: {decoded}")
        except:
            pass
        console.print(f"  Hex: {result.plaintext.hex()}")
    
    if result.metadata:
        console.print(f"\n[dim]Métadonnées: {result.metadata}[/dim]")
    
    console.print("\n" + "="*70 + "\n")


def ask_compute_private_key(factors):
    """Demande si on veut calculer la clé privée"""
    compute = Prompt.ask("\n[yellow]💡 Calculer la clé privée d?[/yellow]", choices=["y", "n"], default="y")
    
    if compute == "y":
        e = IntPrompt.ask("💡 Entrez e", default=65537)
        p, q = factors
        d = PrivateKey(p, q, e)
        console.print(f"\n[bold green]✓ Clé privée calculée: d = {d}[/bold green]\n")


def attack_fermat_variants():
    """Fermat Variants"""
    console.print("\n[bold magenta]🔨 FERMAT VARIANTS ATTACK[/bold magenta]")
    console.print("[green]Versions optimisées: skip2, mod8, adaptive[/green]\n")
    
    n = IntPrompt.ask("💡 Entrez n")
    variant = Prompt.ask("⚙️  Variante", choices=["auto", "skip2", "mod8", "adaptive"], default="auto")
    max_iter = IntPrompt.ask("🔄 Max iterations", default=1000000)
    
    console.print("\n[yellow]⚙️  Lancement...[/yellow]\n")
    
    from lib.attacks.fermat_variants import FermatVariantsAttack
    attack = FermatVariantsAttack(verbose=True, timeout=300)
    result = attack.execute(n=n, variant=variant, max_iterations=max_iter)
    
    display_result(result)
    if result.status == AttackStatus.SUCCESS and result.factors:
        ask_compute_private_key(result.factors)


def attack_williams_p1():
    """Williams p+1"""
    console.print("\n[bold magenta]📈 WILLIAMS p+1 ATTACK[/bold magenta]")
    console.print("[green]Complémentaire à Pollard p-1[/green]\n")
    
    n = IntPrompt.ask("💡 Entrez n")
    B = IntPrompt.ask("📊 Borne B", default=1000000)
    
    console.print("\n[yellow]⚙️  Lancement...[/yellow]\n")
    
    from lib.attacks.williams_p1 import WilliamsP1Attack
    attack = WilliamsP1Attack(verbose=True, timeout=300)
    result = attack.execute(n=n, B=B)
    
    display_result(result)
    if result.status == AttackStatus.SUCCESS and result.factors:
        ask_compute_private_key(result.factors)


def attack_multiprime():
    """Multi-Prime RSA"""
    console.print("\n[bold magenta]🔢 MULTI-PRIME RSA ATTACK[/bold magenta]")
    console.print("[green]RSA avec n = p×q×r×...[/green]\n")
    
    n = IntPrompt.ask("💡 Entrez n")
    num = Prompt.ask("❓ Nombre de facteurs connu?", choices=["y", "n"], default="n")
    num_factors = IntPrompt.ask("💡 Nombre de facteurs") if num == "y" else None
    
    console.print("\n[yellow]⚙️  Lancement...[/yellow]\n")
    
    from lib.attacks.multiprime import MultiPrimeRSAAttack
    attack = MultiPrimeRSAAttack(verbose=True, timeout=300)
    result = attack.execute(n=n, num_factors=num_factors)
    
    display_result(result)


def attack_cube_root():
    """Cube Root Attack"""
    console.print("\n[bold magenta]³√ CUBE ROOT ATTACK[/bold magenta]")
    console.print("[green]e=3 sans padding suffisant[/green]\n")
    
    c = IntPrompt.ask("💡 Entrez c (ciphertext)")
    has_n = Prompt.ask("❓ Avez-vous n?", choices=["y", "n"], default="y")
    n = IntPrompt.ask("💡 Entrez n") if has_n == "y" else None
    e = IntPrompt.ask("💡 Entrez e", default=3)
    
    console.print("\n[yellow]⚙️  Lancement...[/yellow]\n")
    
    from lib.attacks.cube_root import CubeRootAttack
    attack = CubeRootAttack(verbose=True, timeout=300)
    result = attack.execute(c=c, n=n, e=e)
    
    display_result(result)


def attack_small_e_padding():
    """Small e + Padding"""
    console.print("\n[bold magenta]🔢 SMALL e + PADDING ATTACK[/bold magenta]")
    console.print("[green]Détection automatique de faiblesse[/green]\n")
    
    n = IntPrompt.ask("💡 Entrez n")
    e = IntPrompt.ask("💡 Entrez e")
    c = IntPrompt.ask("💡 Entrez c")
    
    console.print("\n[yellow]⚙️  Lancement...[/yellow]\n")
    
    from lib.attacks.small_e_padding import SmallEPaddingAttack
    attack = SmallEPaddingAttack(verbose=True, timeout=300)
    result = attack.execute(n=n, e=e, c=c)
    
    display_result(result)


def attack_lsb_oracle():
    """LSB Oracle Attack"""
    console.print("\n[bold magenta]🔮 LSB ORACLE ATTACK[/bold magenta]")
    console.print("[green]Requiert accès à un oracle LSB[/green]\n")
    console.print("[yellow]⚠️  Cette attaque nécessite une fonction oracle custom.[/yellow]")
    console.print("[cyan]Exemple d'oracle:[/cyan]")
    console.print("[dim]def my_oracle(c): return decrypt(c) % 2 == 0[/dim]\n")
    
    n = IntPrompt.ask("💡 Entrez n")
    e = IntPrompt.ask("💡 Entrez e")
    c = IntPrompt.ask("💡 Entrez c")
    
    console.print("\n[yellow]Mode simulation (oracle fictif pour démo)[/yellow]")
    
    # Mode simulation
    secret = IntPrompt.ask("💡 Message secret (simulation)")
    
    def demo_oracle(ciphertext):
        """Oracle de démonstration"""
        m = pow(ciphertext, 0, n)  # Simulé
        return secret % 2 == 0
    
    console.print("\n[yellow]⚙️  Lancement...[/yellow]\n")
    console.print("[dim]Pour utilisation réelle, modifiez la fonction oracle dans le code[/dim]")
    
    from lib.attacks.lsb_oracle import LSBOracleAttack
    attack = LSBOracleAttack(verbose=True, timeout=300)
    result = attack.execute(n=n, e=e, c=c, oracle_func=demo_oracle)
    
    display_result(result)


def attack_batch_gcd():
    """Batch GCD Attack"""
    console.print("\n[bold magenta]🔍 BATCH GCD ATTACK[/bold magenta]")
    console.print("[green]Trouver des facteurs communs dans une liste de modules[/green]\n")
    
    num = IntPrompt.ask("💡 Nombre de modules à tester")
    moduli = []
    
    for i in range(num):
        n = IntPrompt.ask(f"💡 Module n{i+1}")
        moduli.append(n)
    
    console.print("\n[yellow]⚙️  Lancement...[/yellow]\n")
    
    from lib.attacks.batch_gcd import BatchGCDAttack
    attack = BatchGCDAttack(verbose=True, timeout=300)
    result = attack.execute(moduli=moduli)
    
    display_result(result)


def attack_partial_key():
    """Partial Key Exposure"""
    console.print("\n[bold magenta]🔑 PARTIAL KEY EXPOSURE[/bold magenta]")
    console.print("[green]Exploitation de bits connus de la clé[/green]\n")
    
    n = IntPrompt.ask("💡 Entrez n")
    known_bits = Prompt.ask("💡 Bits connus (string binaire, ex: 10110...)")
    position = Prompt.ask("💡 Position", choices=["msb", "lsb"], default="msb")
    
    console.print("\n[yellow]⚙️  Lancement...[/yellow]\n")
    
    from lib.attacks.partial_key import PartialKeyExposureAttack
    attack = PartialKeyExposureAttack(verbose=True, timeout=300)
    result = attack.execute(n=n, known_bits=known_bits, position=position)
    
    display_result(result)
    if result.status == AttackStatus.SUCCESS and result.factors:
        ask_compute_private_key(result.factors)


def attack_known_plaintext():
    """Known Plaintext"""
    console.print("\n[bold magenta]📖 KNOWN PLAINTEXT ATTACK[/bold magenta]")
    console.print("[green]Exploitation d'un couple (m, c) connu[/green]\n")
    
    n = IntPrompt.ask("💡 Entrez n")
    e = IntPrompt.ask("💡 Entrez e")
    m = IntPrompt.ask("💡 Plaintext connu m")
    c = IntPrompt.ask("💡 Ciphertext correspondant c")
    
    console.print("\n[yellow]⚙️  Lancement...[/yellow]\n")
    
    from lib.attacks.known_plaintext import KnownPlaintextAttack
    attack = KnownPlaintextAttack(verbose=True, timeout=300)
    result = attack.execute(n=n, e=e, m=m, c=c)
    
    display_result(result)


def attack_smooth_number():
    """Smooth Number Detection"""
    console.print("\n[bold magenta]🔢 SMOOTH NUMBER DETECTION[/bold magenta]")
    console.print("[green]Analyse de friabilité et recommandations d'attaques[/green]\n")
    
    n = IntPrompt.ask("💡 Entrez n")
    B = IntPrompt.ask("📊 Borne B de test", default=1000000)
    
    console.print("\n[yellow]⚙️  Analyse...[/yellow]\n")
    
    from lib.attacks.smooth_number import SmoothNumberAttack
    attack = SmoothNumberAttack(verbose=True, timeout=300)
    result = attack.execute(n=n, B_test=B)
    
    display_result(result)


def key_loader_menu():
    """Key Loader Universel"""
    console.print("\n[bold magenta]🗝️  UNIVERSAL KEY LOADER[/bold magenta]")
    console.print("[green]Supporte: PEM, DER, SSH, JWK, XML, PGP, PKCS#12...[/green]\n")
    
    source = Prompt.ask("💡 Chemin du fichier ou string de la clé")
    has_pwd = Prompt.ask("❓ Mot de passe?", choices=["y", "n"], default="n")
    password = Prompt.ask("🔑 Mot de passe", password=True) if has_pwd == "y" else None
    
    from lib.utils.key_loader import UniversalKeyLoader
    loader = UniversalKeyLoader(verbose=True)
    
    try:
        key_data = loader.load(source, password)
        loader.display_key_info(key_data)
        
        # Proposer d'utiliser les paramètres extraits
        if key_data.n:
            console.print(f"\n[green]✓ Paramètres disponibles:[/green]")
            console.print(f"  n = {str(key_data.n)[:60]}...")
            if key_data.e:
                console.print(f"  e = {key_data.e}")
            if key_data.d:
                console.print(f"  d = {str(key_data.d)[:60]}...")
            
            use_params = Prompt.ask(
                "\n💡 Lancer une attaque avec ces paramètres?",
                choices=["y", "n"],
                default="y"
            )
            
            if use_params == "y" and key_data.n:
                console.print("[cyan]Paramètres copiés! Retournez au menu.[/cyan]")
    
    except Exception as ex:
        console.print(f"\n[red]✗ Erreur: {ex}[/red]")


def main():
    """Fonction principale"""
    banner()
    
    console.print("[yellow]Framework dédié à l'exploitation des vulnérabilités RSA[/yellow]")
    console.print("[dim]Version 2.0 - Architecture optimisée[/dim]\n")
    
    menu_map = {
        # Factorisation
        1:  attack_fermat,
        2:  attack_fermat_variants,
        3:  attack_pollard_rho,
        4:  attack_pollard_p1,
        5:  attack_williams_p1,
        6:  attack_multiprime,
        # Exposants
        7:  attack_wiener,
        8:  attack_hastad,
        9:  attack_cube_root,
        10: attack_small_e_padding,
        # Oracle
        11: attack_lsb_oracle,
        # Multi-clés
        12: attack_franklin_reiter,
        13: attack_common_modulus,
        14: attack_common_prime,
        15: attack_batch_gcd,
        # Avancées
        16: attack_partial_key,
        17: attack_known_plaintext,
        18: attack_smooth_number,
        # Database
        19: attack_factordb,
        # Utilitaires
        20: rsa_encode_decode,
        21: key_loader_menu,
        22: compute_private_key,
        # Spécial
        99: auto_detect,
    }
    
    while True:
        try:
            show_menu()
            choice = IntPrompt.ask("\n[bold cyan]🎯 Choisir une attaque[/bold cyan]", default=0)
            
            if choice == 0:
                console.print("\n[yellow]👋 Bye Bye H4x0R ![/yellow]\n")
                break
            
            if choice in menu_map:
                menu_map[choice]()
            else:
                console.print("[red]❌ Choix invalide![/red]")
            
            input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")
            console.clear()
            banner()
            
        except KeyboardInterrupt:
            console.print("\n\n[yellow]👋 Bye Bye H4x0R ![/yellow]\n")
            break
        except Exception as ex:
            console.print(f"\n[red]❌ Erreur: {ex}[/red]\n")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()