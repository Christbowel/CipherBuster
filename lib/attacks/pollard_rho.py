"""
Pollard's Rho Attack - Implémentation optimisée avec algorithme de Floyd
"""

import math
from .base import BaseAttack, AttackResult, AttackStatus
from ..utils.math_utils import gcd


class PollardRhoAttack(BaseAttack):
    """
    Attaque de Pollard Rho pour factoriser n.
    
    Utilise l'algorithme de Floyd (tortue et lièvre) pour détecter les cycles.
    Complexité: O(√p) où p est le plus petit facteur premier de n
    """
    
    def execute(self, n: int, max_iterations: int = 1000000, **params) -> AttackResult:
        """
        Exécute l'attaque de Pollard Rho
        
        Args:
            n: Module RSA à factoriser
            max_iterations: Nombre max d'itérations
        """
        self._start_timer()
        self.log(f"Démarrage Pollard's Rho sur n={n}", "INFO")
        
        # Vérifications basiques
        if n <= 1:
            return AttackResult(
                status=AttackStatus.FAILED,
                message="n doit être > 1"
            )
        
        if n % 2 == 0:
            self.log("n est pair, facteur trouvé immédiatement", "SUCCESS")
            return AttackResult(
                status=AttackStatus.SUCCESS,
                factors=(2, n // 2),
                time_elapsed=self._elapsed_time(),
                message="Factorisation réussie"
            )
        
        # Fonction polynomiale f(x) = (x² + c) mod n
        def f(x, c, n):
            return (x * x + c) % n
        
        # Essayer plusieurs valeurs de c
        for c in [1, 2, 3, 5, 7]:
            self.log(f"Tentative avec c={c}", "INFO")
            
            x = 2  # Tortue
            y = 2  # Lièvre
            d = 1
            
            iterations = 0
            while d == 1 and iterations < max_iterations:
                # Tortue fait 1 pas
                x = f(x, c, n)
                
                # Lièvre fait 2 pas
                y = f(f(y, c, n), c, n)
                
                # Calculer GCD
                d = gcd(abs(x - y), n)
                
                iterations += 1
                
                # Log périodique
                if self.verbose and iterations % 10000 == 0:
                    self.log(f"Itération {iterations}...", "INFO")
                
                # Vérifier timeout
                if self._check_timeout():
                    self.log("Timeout atteint", "WARNING")
                    return AttackResult(
                        status=AttackStatus.TIMEOUT,
                        time_elapsed=self._elapsed_time(),
                        iterations=iterations,
                        message="Timeout"
                    )
            
            # Vérifier si un facteur a été trouvé
            if d != 1 and d != n:
                p = d
                q = n // d
                
                self.log(f"✓ Facteurs trouvés en {iterations} itérations!", "SUCCESS")
                self.log(f"p = {p}, q = {q}", "SUCCESS")
                
                return AttackResult(
                    status=AttackStatus.SUCCESS,
                    factors=(int(p), int(q)),
                    time_elapsed=self._elapsed_time(),
                    iterations=iterations,
                    message=f"Factorisation réussie avec c={c}",
                    metadata={"c": c}
                )
        
        # Échec après avoir testé tous les c
        self.log("Échec de la factorisation", "ERROR")
        return AttackResult(
            status=AttackStatus.FAILED,
            time_elapsed=self._elapsed_time(),
            iterations=max_iterations,
            message="Aucun facteur trouvé"
        )