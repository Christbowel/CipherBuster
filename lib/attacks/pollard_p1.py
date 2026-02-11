"""
Pollard's p-1 Attack - Version optimisée
"""

import math
from .base import BaseAttack, AttackResult, AttackStatus
from ..utils.math_utils import gcd


class PollardP1Attack(BaseAttack):
    """
    Attaque de Pollard p-1
    
    Fonctionne si p-1 est B-friable (tous ses facteurs premiers sont ≤ B)
    Complexité: O(B log B)
    """
    
    def execute(self, n: int, B: int = 1000000, **params) -> AttackResult:
        """
        Exécute l'attaque de Pollard p-1
    
        Args:
            n: Module RSA
            B: Borne de friabilité
        """
        self._start_timer()
        self.log(f"Démarrage Pollard's p-1 avec B={B}", "INFO")
    
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
    
        # Générer les nombres premiers
        primes = self._sieve_of_eratosthenes(B)
        self.log(f"Utilisation de {len(primes)} premiers ≤ {B}", "INFO")
    
        # Phase 1
        a = 2
    
        for i, p in enumerate(primes):
            # Calculer la plus grande puissance de p ≤ B
            p_power = p
            while p_power * p <= B:
                p_power *= p
        
            a = pow(a, p_power, n)
        
            # Vérifier GCD périodiquement
            if i % 20 == 0:
                from ..utils.math_utils import gcd
                g = gcd(a - 1, n)
                if 1 < g < n:
                    p_factor = g
                    q_factor = n // g
                    self.log(f"✓ Facteurs trouvés tôt!", "SUCCESS")
                    return AttackResult(
                        status=AttackStatus.SUCCESS,
                        factors=(int(p_factor), int(q_factor)),
                        time_elapsed=self._elapsed_time(),
                        message=f"Factorisation Pollard p-1",
                        metadata={"B": B}
                    )
        
            if self.verbose and i % 100 == 0:
                self.log(f"Premiers: {i}/{len(primes)}", "INFO")
        
            if self._check_timeout():
                return AttackResult(
                    status=AttackStatus.TIMEOUT,
                    time_elapsed=self._elapsed_time(),
                    message="Timeout"
                )
    
        # Vérification finale
        from ..utils.math_utils import gcd
        g = gcd(a - 1, n)
    
        if 1 < g < n:
            p_factor = g
            q_factor = n // g
            self.log(f"✓ Facteurs trouvés!", "SUCCESS")
            return AttackResult(
                status=AttackStatus.SUCCESS,
                factors=(int(p_factor), int(q_factor)),
                time_elapsed=self._elapsed_time(),
                message=f"Factorisation réussie avec B={B}",
                metadata={"B": B}
            )
    
        return AttackResult(
            status=AttackStatus.FAILED,
            time_elapsed=self._elapsed_time(),
            message=f"p-1 non {B}-friable, essayez B plus grand"
        )
    
    def _sieve_of_eratosthenes(self, limit: int) -> list:
        """Crible d'Ératosthène pour générer les nombres premiers ≤ limit"""
        if limit < 2:
            return []
        
        sieve = [True] * (limit + 1)
        sieve[0] = sieve[1] = False
        
        for i in range(2, int(math.sqrt(limit)) + 1):
            if sieve[i]:
                for j in range(i*i, limit + 1, i):
                    sieve[j] = False
        
        return [i for i in range(2, limit + 1) if sieve[i]]