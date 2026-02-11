"""
Auto-Detector - Analyse automatique et suggestion d'attaques
"""

from rich.console import Console
from rich.table import Table


class RSAAnalyzer:
    """Analyseur intelligent de clés RSA"""
    
    def __init__(self):
        self.console = Console()
    
    def analyze(self, n: int = None, e: int = None, c: int = None, **params):
        """
        Analyse les paramètres RSA et suggère les attaques appropriées
        
        Returns:
            Liste d'attaques recommandées par ordre de probabilité
        """
        suggestions = []
        
        self.console.print("\n[bold cyan]🔍 ANALYSE AUTOMATIQUE[/bold cyan]\n")
        
        # Créer tableau d'analyse
        table = Table(title="Analyse de la clé RSA")
        table.add_column("Propriété", style="cyan")
        table.add_column("Valeur", style="yellow")
        table.add_column("Verdict", style="green")
        
        if n is not None:
            n_bits = n.bit_length()
            table.add_row("Taille de n", f"{n_bits} bits", self._verdict_size(n_bits))
            
            # Vérifier si n est petit
            if n_bits < 512:
                suggestions.append(("factordb", "HAUTE", "n est très petit"))
                suggestions.append(("fermat", "HAUTE", "Essayer Fermat"))
            
            # Vérifier si n est pair
            if n % 2 == 0:
                suggestions.append(("trivial", "CRITIQUE", "n est pair!"))
            
            # Vérifier la forme de n pour Fermat
            import math
            sqrt_n = math.isqrt(n)
            if (sqrt_n + 1000) ** 2 > n:
                suggestions.append(("fermat", "HAUTE", "p et q probablement proches"))
        
        if e is not None:
            table.add_row("Exposant e", str(e), self._verdict_e(e))
            
            # e petit
            if e == 3:
                suggestions.append(("hastad", "HAUTE", "e=3 (Broadcast Attack possible)"))
            elif e < 65537:
                suggestions.append(("hastad", "MOYENNE", "Petit e"))
            
            # e très grand (Wiener)
            if n is not None and e > n ** 0.5:
                suggestions.append(("wiener", "HAUTE", "e très grand → d peut être petit"))
        
        if c is not None:
            table.add_row("Ciphertext", f"{str(c)[:50]}...", "✓")
        
        self.console.print(table)
        
        # Afficher suggestions
        if suggestions:
            self.console.print("\n[bold yellow]💡 ATTAQUES RECOMMANDÉES:[/bold yellow]\n")
            
            sugg_table = Table()
            sugg_table.add_column("Priorité", style="bold")
            sugg_table.add_column("Attaque", style="cyan")
            sugg_table.add_column("Raison", style="white")
            
            # Trier par priorité
            priority_order = {"CRITIQUE": 0, "HAUTE": 1, "MOYENNE": 2, "BASSE": 3}
            suggestions.sort(key=lambda x: priority_order.get(x[1], 4))
            
            for attack, priority, reason in suggestions:
                color = {
                    "CRITIQUE": "red",
                    "HAUTE": "yellow",
                    "MOYENNE": "blue",
                    "BASSE": "white"
                }.get(priority, "white")
                
                sugg_table.add_row(
                    f"[{color}]{priority}[/{color}]",
                    attack,
                    reason
                )
            
            self.console.print(sugg_table)
        
        return suggestions
    
    def _verdict_size(self, bits: int) -> str:
        if bits < 512:
            return "⚠️  TRÈS FAIBLE"
        elif bits < 1024:
            return "⚠️  FAIBLE"
        elif bits < 2048:
            return "✓ ACCEPTABLE"
        else:
            return "✓ FORT"
    
    def _verdict_e(self, e: int) -> str:
        if e == 3:
            return "⚠️  Très petit"
        elif e == 65537:
            return "✓ Standard"
        elif e > 65537:
            return "⚠️  Grand (Wiener?)"
        else:
            return "✓ OK"