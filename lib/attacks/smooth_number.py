"""
Smooth Number Detection
Détecte si n ou p-1/q-1 sont friables (smooth)
"""

from .base import BaseAttack, AttackResult, AttackStatus
import math


class SmoothNumberAttack(BaseAttack):
    """
    Détection de nombres friables (smooth numbers)
    
    Un nombre est B-friable si tous ses facteurs premiers sont ≤ B.
    
    Analyse:
    - Si n est friable → facile à factoriser
    - Si p-1 est friable → Pollard p-1
    - Si p+1 est friable → Williams p+1
    """
    
    def execute(self, n: int, B_test: int = 1000000, **params) -> AttackResult:
        """
        Analyse la friabilité de n
        
        Args:
            n: Nombre à analyser
            B_test: Borne de test
        """
        self._start_timer()
        self.log(f"Analyse de friabilité avec B={B_test}", "INFO")
        
        # Tester si n lui-même est friable
        factors = self._trial_factorization(n, B_test)
        
        if factors and math.prod(factors) == n:
            self.log(f"✓ n est {B_test}-friable!", "SUCCESS")
            self.log(f"Facteurs: {factors}", "SUCCESS")
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                factors=tuple(factors) if len(factors) == 2 else None,
                time_elapsed=self._elapsed_time(),
                message=f"n est {B_test}-friable",
                metadata={
                    "smooth": True,
                    "B": B_test,
                    "all_factors": factors,
                    "largest_factor": max(factors),
                    "recommendation": "n facile à factoriser"
                }
            )
        
        # Estimer la friabilité
        largest_factor_found = max(factors) if factors else 0
        smoothness_score = self._compute_smoothness(n, factors, B_test)
        
        self.log(f"Plus grand facteur trouvé ≤ {B_test}: {largest_factor_found}", "INFO")
        self.log(f"Score de friabilité: {smoothness_score:.2f}", "INFO")
        
        # Recommandations
        recommendations = []
        
        if smoothness_score > 0.5:
            recommendations.append("Pollard p-1 recommandé")
        
        if smoothness_score > 0.3:
            recommendations.append("Williams p+1 possible")
        
        if largest_factor_found > B_test / 2:
            recommendations.append("Augmenter la borne B")
        
        if not recommendations:
            recommendations.append("n semble résistant aux attaques de friabilité")
        
        self.log(f"Recommandations: {', '.join(recommendations)}", "INFO")
        
        return AttackResult(
            status=AttackStatus.PARTIAL,
            time_elapsed=self._elapsed_time(),
            message="Analyse de friabilité complète",
            metadata={
                "smooth": False,
                "smoothness_score": smoothness_score,
                "factors_found": factors,
                "largest_factor": largest_factor_found,
                "recommendations": recommendations
            }
        )
    
    def _trial_factorization(self, n: int, limit: int) -> list:
        """Factorisation par division (nombres ≤ limit)"""
        factors = []
        d = 2
        
        while d <= limit and n > 1:
            while n % d == 0:
                factors.append(d)
                n //= d
            
            d += 1 if d == 2 else 2  # Skip even numbers after 2
            
            if self._check_timeout():
                break
        
        if n > 1 and n != factors:
            factors.append(n)  # Facteur restant
        
        return factors
    
    def _compute_smoothness(self, n: int, factors: list, B: int) -> float:
        """Calcule un score de friabilité [0, 1]"""
        if not factors:
            return 0.0
        
        # Score basé sur le plus grand facteur trouvé
        largest = max(factors)
        
        if largest <= B:
            return 1.0
        
        # Score partiel
        score = math.log(B) / math.log(largest) if largest > B else 1.0
        return max(0.0, min(1.0, score))