"""
Fermat Factorization Variants
Versions optimisées de Fermat avec différentes stratégies
"""

from .base import BaseAttack, AttackResult, AttackStatus
from ..utils.math_utils import isqrt, gcd
import math


class FermatVariantsAttack(BaseAttack):
    """
    Variantes optimisées de Fermat
    
    - Skip de 2 (pour nombres impairs)
    - Modulo 8 optimization
    - Multiple starting points
    - Adaptive step size
    """
    
    def execute(self, n: int, variant: str = "auto", max_iterations: int = 1000000, 
                **params) -> AttackResult:
        """
        Exécute une variante de Fermat
        
        Args:
            n: Module RSA
            variant: "skip2", "mod8", "adaptive", "auto"
            max_iterations: Max iterations
        """
        self._start_timer()
        self.log(f"Démarrage Fermat Variant: {variant}", "INFO")
        
        if n <= 1:
            return AttackResult(status=AttackStatus.FAILED, message="n ≤ 1")
        
        if n % 2 == 0:
            return AttackResult(
                status=AttackStatus.SUCCESS,
                factors=(2, n // 2),
                time_elapsed=self._elapsed_time(),
                message="n pair"
            )
        
        if variant == "auto":
            if n % 8 == 1:
                variant = "mod8"
            else:
                variant = "skip2"
            self.log(f"Variante auto-sélectionnée: {variant}", "INFO")
        
        if variant == "skip2":
            return self._fermat_skip2(n, max_iterations)
        elif variant == "mod8":
            return self._fermat_mod8(n, max_iterations)
        elif variant == "adaptive":
            return self._fermat_adaptive(n, max_iterations)
        else:
            return AttackResult(
                status=AttackStatus.FAILED,
                message=f"Variante inconnue: {variant}"
            )
    
    def _fermat_skip2(self, n: int, max_iter: int) -> AttackResult:
        """Fermat avec saut de 2 (nombres impairs)"""
        self.log("Variante Skip-2 (optimisée pour impairs)", "INFO")
        
        a = isqrt(n)
        if a * a < n:
            a += 1
        
        if a % 2 == 0:
            a += 1
        
        for i in range(0, max_iter, 2):
            b_sq = a * a - n
            b = isqrt(b_sq)
            
            if b * b == b_sq:
                p, q = a + b, a - b
                
                if p * q == n:
                    self.log(f"✓ Trouvé en {i//2 + 1} itérations!", "SUCCESS")
                    return AttackResult(
                        status=AttackStatus.SUCCESS,
                        factors=(int(p), int(q)),
                        time_elapsed=self._elapsed_time(),
                        iterations=i // 2 + 1,
                        message="Fermat Skip-2",
                        metadata={"variant": "skip2", "speedup": "2x"}
                    )
            
            a += 2  
            
            if self.verbose and i % 20000 == 0:
                self.log(f"Itération {i//2}...", "INFO")
            
            if self._check_timeout():
                return AttackResult(status=AttackStatus.TIMEOUT, iterations=i//2)
        
        return AttackResult(
            status=AttackStatus.FAILED,
            iterations=max_iter // 2,
            message="Max iterations"
        )
    
    def _fermat_mod8(self, n: int, max_iter: int) -> AttackResult:
        """Fermat avec optimisation modulo 8"""
        self.log("Variante Mod-8 (analyse résidus quadratiques)", "INFO")
        
        # Si n ≡ 1 (mod 8), alors a² - n ≡ 0 ou 1 (mod 8)
        # On peut sauter certaines valeurs
        
        a = isqrt(n)
        if a * a < n:
            a += 1
        
        # Ajuster selon n mod 8
        n_mod8 = n % 8
        skip = 4 if n_mod8 == 1 else 2
        
        self.log(f"n ≡ {n_mod8} (mod 8), skip={skip}", "INFO")
        
        for i in range(0, max_iter, skip):
            b_sq = a * a - n
            b = isqrt(b_sq)
            
            if b * b == b_sq:
                p, q = a + b, a - b
                
                if p * q == n:
                    self.log(f"✓ Trouvé avec Mod-8!", "SUCCESS")
                    return AttackResult(
                        status=AttackStatus.SUCCESS,
                        factors=(int(p), int(q)),
                        time_elapsed=self._elapsed_time(),
                        iterations=i // skip + 1,
                        message="Fermat Mod-8",
                        metadata={"variant": "mod8", "speedup": f"{skip}x"}
                    )
            
            a += skip
            
            if self._check_timeout():
                return AttackResult(status=AttackStatus.TIMEOUT, iterations=i//skip)
        
        return AttackResult(status=AttackStatus.FAILED, iterations=max_iter//skip)
    
    def _fermat_adaptive(self, n: int, max_iter: int) -> AttackResult:
        """Fermat avec pas adaptatif"""
        self.log("Variante Adaptive (pas variable)", "INFO")
        
        a = isqrt(n)
        if a * a < n:
            a += 1
        
        step = 1
        
        for i in range(max_iter):
            b_sq = a * a - n
            b = isqrt(b_sq)
            
            if b * b == b_sq:
                p, q = a + b, a - b
                
                if p * q == n:
                    self.log(f"✓ Trouvé avec step adaptatif!", "SUCCESS")
                    return AttackResult(
                        status=AttackStatus.SUCCESS,
                        factors=(int(p), int(q)),
                        time_elapsed=self._elapsed_time(),
                        iterations=i + 1,
                        message="Fermat Adaptive"
                    )
            
            diff = b_sq - b * b
            if diff > 1000:
                step = min(10, diff // 1000)
            else:
                step = 1
            
            a += step
            
            if self._check_timeout():
                return AttackResult(status=AttackStatus.TIMEOUT, iterations=i)
        
        return AttackResult(status=AttackStatus.FAILED, iterations=max_iter)