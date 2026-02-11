"""
Williams p+1 Factorization
Similaire à Pollard p-1 mais pour p+1
"""

from .base import BaseAttack, AttackResult, AttackStatus
from ..utils.math_utils import gcd
import math


class WilliamsP1Attack(BaseAttack):
    """
    Attaque de Williams p+1
    
    Fonctionne si p+1 est B-friable (tous ses facteurs premiers ≤ B)
    Complémentaire à Pollard p-1
    
    Complexité: O(B log B)
    """
    
    def execute(self, n: int, B: int = 1000000, **params) -> AttackResult:
        """
        Exécute Williams p+1
        
        Args:
            n: Module RSA
            B: Borne de friabilité
        """
        self._start_timer()
        self.log(f"Démarrage Williams p+1 avec B={B}", "INFO")
        
        if n <= 1:
            return AttackResult(
                status=AttackStatus.FAILED,
                message="n doit être > 1"
            )
        
        if n % 2 == 0:
            return AttackResult(
                status=AttackStatus.SUCCESS,
                factors=(2, n // 2),
                time_elapsed=self._elapsed_time(),
                message="n est pair"
            )
        
        # Utiliser la suite de Lucas
        # V_0 = 2, V_1 = A
        # V_{k+1} = A*V_k - V_{k-1}
        
        A = 3  # Paramètre de départ
        
        # Générer les nombres premiers
        primes = self._sieve_of_eratosthenes(B)
        self.log(f"Utilisation de {len(primes)} nombres premiers ≤ {B}", "INFO")
        
        # Calculer V_M où M = produit des petits premiers
        V_prev = 2
        V_curr = A
        
        for i, p in enumerate(primes):
            # Calculer la plus grande puissance de p ≤ B
            p_power = p
            while p_power * p <= B:
                p_power *= p
            
            # Calculer V_{p_power}
            for _ in range(p_power - 1):
                V_next = (A * V_curr - V_prev) % n
                V_prev = V_curr
                V_curr = V_next
            
            # Log périodique
            if self.verbose and i % 100 == 0:
                self.log(f"Traitement des premiers: {i}/{len(primes)}", "INFO")
            
            # Vérifier timeout
            if self._check_timeout():
                return AttackResult(
                    status=AttackStatus.TIMEOUT,
                    time_elapsed=self._elapsed_time(),
                    message="Timeout"
                )
        
        # Calculer GCD(V_M - 2, n)
        g = gcd(V_curr - 2, n)
        
        if 1 < g < n:
            p = g
            q = n // g
            
            self.log(f"✓ Facteurs trouvés!", "SUCCESS")
            self.log(f"p = {p}, q = {q}", "SUCCESS")
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                factors=(int(p), int(q)),
                time_elapsed=self._elapsed_time(),
                message=f"Factorisation réussie avec B={B}",
                metadata={"B": B, "method": "williams_p1"}
            )
        
        self.log("Échec: aucun facteur trouvé", "ERROR")
        return AttackResult(
            status=AttackStatus.FAILED,
            time_elapsed=self._elapsed_time(),
            message=f"p+1 n'est probablement pas {B}-friable"
        )
    
    def _sieve_of_eratosthenes(self, limit: int) -> list:
        """Crible d'Ératosthène"""
        if limit < 2:
            return []
        
        sieve = [True] * (limit + 1)
        sieve[0] = sieve[1] = False
        
        for i in range(2, int(math.sqrt(limit)) + 1):
            if sieve[i]:
                for j in range(i*i, limit + 1, i):
                    sieve[j] = False
        
        return [i for i in range(2, limit + 1) if sieve[i]]