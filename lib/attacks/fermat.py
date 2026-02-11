"""
Fermat's Factorization Attack
"""

import math
from .base import BaseAttack, AttackResult, AttackStatus
from ..utils.math_utils import isqrt


class FermatAttack(BaseAttack):
    """
    Attaque de Fermat pour factoriser n quand p et q sont proches.
    
    Principe: Si n = pq avec p ≈ q, alors n = a² - b²
    Complexité: O(|p-q|)
    """
    
    def execute(self, n: int, max_iterations: int = 1000000, **params) -> AttackResult:
        """
        Exécute l'attaque de Fermat
        
        Args:
            n: Module RSA
            max_iterations: Nombre max d'itérations
        """
        self._start_timer()
        self.log(f"Démarrage attaque de Fermat sur n={n}", "INFO")
        
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
        
        a = isqrt(n)
        if a * a < n:
            a += 1
        
        self.log(f"Valeur initiale: a = {a}", "INFO")
        
        for iteration in range(max_iterations):
            # b² = a² - n
            b_squared = a * a - n
            b = isqrt(b_squared)
            
            # Si b est entier, on a trouvé les facteurs
            if b * b == b_squared:
                p = a + b
                q = a - b
                
                if p * q == n:
                    self.log(f"✓ Facteurs trouvés en {iteration + 1} itérations!", "SUCCESS")
                    self.log(f"p = {p}, q = {q}", "SUCCESS")
                    self.log(f"Différence |p-q| = {abs(p-q)}", "INFO")
                    
                    return AttackResult(
                        status=AttackStatus.SUCCESS,
                        factors=(int(p), int(q)),
                        time_elapsed=self._elapsed_time(),
                        iterations=iteration + 1,
                        message="Factorisation réussie",
                        metadata={"difference": abs(p-q)}
                    )
            
            a += 1
            
            # Log périodique
            if self.verbose and iteration % 10000 == 0 and iteration > 0:
                self.log(f"Itération {iteration}", "INFO")
            
            # Vérifier timeout
            if self._check_timeout():
                return AttackResult(
                    status=AttackStatus.TIMEOUT,
                    time_elapsed=self._elapsed_time(),
                    iterations=iteration,
                    message="Timeout"
                )
        
        self.log("Échec: max iterations atteint", "ERROR")
        return AttackResult(
            status=AttackStatus.FAILED,
            time_elapsed=self._elapsed_time(),
            iterations=max_iterations,
            message="p et q sont probablement trop éloignés pour Fermat"
        )