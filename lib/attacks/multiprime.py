"""
Multi-Prime RSA Attack
RSA avec n = p*q*r (3+ facteurs premiers)
"""

from .base import BaseAttack, AttackResult, AttackStatus
from ..utils.math_utils import gcd
import math


class MultiPrimeRSAAttack(BaseAttack):
    """
    Attaque sur RSA multi-premiers
    
    Au lieu de n = p*q, on a n = p*q*r*...
    Généralement plus faible car plus de facteurs = plus facile à casser
    
    Stratégies:
    - Fermat adapté
    - Pollard Rho (trouve un facteur, puis récursif)
    - Détection du nombre de facteurs
    """
    
    def execute(self, n: int, num_factors: int = None, **params) -> AttackResult:
        """
        Exécute l'attaque Multi-Prime
        
        Args:
            n: Module RSA
            num_factors: Nombre de facteurs (si connu)
        """
        self._start_timer()
        self.log(f"Démarrage Multi-Prime RSA Attack", "INFO")
        
        if num_factors:
            self.log(f"Nombre de facteurs attendu: {num_factors}", "INFO")
        else:
            self.log("Nombre de facteurs inconnu, détection automatique", "INFO")
        
        # Trouver tous les facteurs
        factors = []
        remaining = n
        
        # Utiliser Pollard Rho itérativement
        from .pollard_rho import PollardRhoAttack
        
        max_iterations = 10  # Max 10 facteurs
        iteration = 0
        
        while remaining > 1 and iteration < max_iterations:
            self.log(f"Recherche facteur #{iteration + 1} de {remaining}...", "INFO")
            
            # Vérifier si remaining est premier
            if self._is_probably_prime(remaining):
                factors.append(remaining)
                self.log(f"✓ Dernier facteur (premier): {remaining}", "SUCCESS")
                break
            
            # Tenter Pollard Rho
            pollard = PollardRhoAttack(verbose=False, timeout=30)
            result = pollard.execute(n=remaining, max_iterations=100000)
            
            if result.status == AttackStatus.SUCCESS and result.factors:
                p, q = result.factors
                self.log(f"✓ Facteur trouvé: {p}", "SUCCESS")
                
                factors.append(p)
                remaining = q
            else:
                # Pollard a échoué, essayer simple division
                factor = self._trial_division(remaining, limit=10000)
                if factor and factor > 1:
                    factors.append(factor)
                    remaining = remaining // factor
                    self.log(f"✓ Facteur (division): {factor}", "SUCCESS")
                else:
                    self.log("Impossible de factoriser davantage", "WARNING")
                    break
            
            iteration += 1
            
            if self._check_timeout():
                return AttackResult(
                    status=AttackStatus.TIMEOUT,
                    time_elapsed=self._elapsed_time(),
                    message="Timeout"
                )
        
        # Vérification
        if factors:
            product = math.prod(factors)
            
            if product == n:
                self.log(f"✓ Factorisation complète: {len(factors)} facteurs!", "SUCCESS")
                for i, f in enumerate(factors, 1):
                    self.log(f"  Facteur {i}: {f}", "SUCCESS")
                
                return AttackResult(
                    status=AttackStatus.SUCCESS,
                    factors=tuple(factors),
                    time_elapsed=self._elapsed_time(),
                    message=f"Factorisation multi-prime réussie ({len(factors)} facteurs)",
                    metadata={
                        "num_factors": len(factors),
                        "all_factors": factors
                    }
                )
            else:
                self.log(f"⚠ Factorisation partielle: {factors}", "WARNING")
                self.log(f"  Produit: {product}, attendu: {n}", "WARNING")
                
                return AttackResult(
                    status=AttackStatus.PARTIAL,
                    factors=tuple(factors),
                    time_elapsed=self._elapsed_time(),
                    message="Factorisation partielle",
                    metadata={
                        "found_factors": factors,
                        "remaining": remaining
                    }
                )
        
        return AttackResult(
            status=AttackStatus.FAILED,
            time_elapsed=self._elapsed_time(),
            message="Aucun facteur trouvé"
        )
    
    def _is_probably_prime(self, n: int, trials: int = 20) -> bool:
        """Test de primalité Miller-Rabin"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Miller-Rabin
        import random
        
        # Écrire n-1 comme 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Test avec trials témoins
        for _ in range(trials):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def _trial_division(self, n: int, limit: int = 10000) -> int:
        """Division par petits nombres premiers"""
        if n % 2 == 0:
            return 2
        
        for i in range(3, min(limit, int(math.sqrt(n)) + 1), 2):
            if n % i == 0:
                return i
        
        return None