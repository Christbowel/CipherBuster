"""
Wiener's Attack - Version corrigée
"""

from .base import BaseAttack, AttackResult, AttackStatus
import sympy
from ..utils.math_utils import gcd


class WienerAttack(BaseAttack):
    """
    Attaque de Wiener pour retrouver d quand d est petit.
    
    Fonctionne si d < n^0.25
    Utilise les fractions continues pour retrouver k/d ≈ e/φ(n)
    """
    
    def execute(self, n: int, e: int, c: int = None, **params) -> AttackResult:
        """
        Exécute l'attaque de Wiener
        
        Args:
            n: Module RSA
            e: Exposant public
            c: Ciphertext (optionnel, pour vérification)
        """
        self._start_timer()
        self.log(f"Démarrage attaque de Wiener", "INFO")
        self.log(f"n = {n}", "INFO")
        self.log(f"e = {e}", "INFO")
        
        if e >= n:
            return AttackResult(
                status=AttackStatus.FAILED,
                message="e doit être < n"
            )
        
        # Calculer les fractions continues de e/n
        convergents = self._continued_fraction_convergents(e, n)
        self.log(f"Analyse de {len(convergents)} convergents", "INFO")
        
        for i, (k, d) in enumerate(convergents):
            # Vérifier que d est valide
            if d <= 0:
                continue
            
            # Vérifier si c'est le bon d
            # Condition: e*d ≡ 1 (mod φ(n))
            # On essaie de retrouver φ(n) avec k et d
            
            if k == 0:
                continue
            
            # φ(n) ≈ (e*d - 1) / k
            phi_n = (e * d - 1) // k
            
            # Vérifier si φ(n) est valide
            # Si oui, on peut retrouver p et q avec n et φ(n)
            # n = p*q et φ(n) = (p-1)*(q-1) = n - p - q + 1
            # Donc: p + q = n - φ(n) + 1
            
            s = n - phi_n + 1  # p + q
            
            # Résoudre p et q avec:
            # p + q = s
            # p * q = n
            # => p et q sont racines de: x² - s*x + n = 0
            
            discriminant = s * s - 4 * n
            
            if discriminant >= 0:
                from math import isqrt
                sqrt_d = isqrt(discriminant)
                
                if sqrt_d * sqrt_d == discriminant:
                    p = (s + sqrt_d) // 2
                    q = (s - sqrt_d) // 2
                    
                    # Vérifier
                    if p * q == n and p > 1 and q > 1:
                        # Vérifier que e*d ≡ 1 (mod φ(n))
                        real_phi = (p - 1) * (q - 1)
                        if (e * d) % real_phi == 1:
                            self.log(f"✓ Clé privée trouvée!", "SUCCESS")
                            self.log(f"d = {d}", "SUCCESS")
                            self.log(f"p = {p}, q = {q}", "SUCCESS")
                            
                            result = AttackResult(
                                status=AttackStatus.SUCCESS,
                                private_key=int(d),
                                factors=(int(p), int(q)),
                                time_elapsed=self._elapsed_time(),
                                message="Attaque réussie",
                                metadata={
                                    "convergent_index": i,
                                    "k": k,
                                    "phi_n": real_phi
                                }
                            )
                            
                            # Si ciphertext fourni, déchiffrer
                            if c is not None:
                                m = pow(c, d, n)
                                result.plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                                self.log(f"Message déchiffré: {m}", "SUCCESS")
                            
                            return result
            
            # Log périodique
            if self.verbose and i % 10 == 0:
                self.log(f"Convergent {i}/{len(convergents)} testé", "INFO")
            
            # Vérifier timeout
            if self._check_timeout():
                return AttackResult(
                    status=AttackStatus.TIMEOUT,
                    time_elapsed=self._elapsed_time(),
                    message="Timeout"
                )
        
        self.log("Échec: d n'est probablement pas assez petit", "ERROR")
        return AttackResult(
            status=AttackStatus.FAILED,
            time_elapsed=self._elapsed_time(),
            message="d > n^0.25 (Wiener ne s'applique pas)"
        )
    
    def _continued_fraction_convergents(self, e: int, n: int) -> list:
        """Calcule les convergents de la fraction continue de e/n"""
        convergents = []
        
        # Calculer la fraction continue
        cf = list(self._continued_fraction(e, n))
        
        # Calculer les convergents
        for i in range(len(cf)):
            k, d = self._convergent(cf[:i+1])
            convergents.append((k, d))
        
        return convergents
    
    def _continued_fraction(self, e: int, n: int):
        """Générateur de fraction continue"""
        while n:
            yield e // n
            e, n = n, e % n
    
    def _convergent(self, cf: list) -> tuple:
        """Calcule le convergent d'une fraction continue"""
        if not cf:
            return (0, 1)
        
        num = 1
        denom = cf[-1]
        
        for i in range(len(cf) - 2, -1, -1):
            num, denom = denom, cf[i] * denom + num
        
        return (denom, num)