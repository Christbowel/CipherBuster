"""
Known Plaintext Attack
Si on connaît un plaintext et son ciphertext correspondant
"""

from .base import BaseAttack, AttackResult, AttackStatus
from ..utils.math_utils import gcd
import math


class KnownPlaintextAttack(BaseAttack):
    """
    Attaque par plaintext connu
    
    Si on a (m, c) tel que c = m^e mod n,
    on peut essayer de factoriser n en utilisant cette information.
    
    Méthode: GCD(m^e - c, n) pourrait révéler un facteur
    """
    
    def execute(self, n: int, e: int, m: int, c: int, **params) -> AttackResult:
        """
        Exécute l'attaque Known Plaintext
        
        Args:
            n: Module RSA
            e: Exposant public
            m: Plaintext connu
            c: Ciphertext correspondant
        """
        self._start_timer()
        self.log(f"Démarrage Known Plaintext Attack", "INFO")
        
        # Vérification: c = m^e mod n ?
        expected_c = pow(m, e, n)
        
        if expected_c != c:
            self.log(f"⚠ c ≠ m^e mod n", "WARNING")
            self.log(f"  Attendu: {expected_c}", "WARNING")
            self.log(f"  Reçu: {c}", "WARNING")
            return AttackResult(
                status=AttackStatus.FAILED,
                message="Plaintext/Ciphertext incorrects"
            )
        
        self.log("✓ Relation c = m^e mod n vérifiée", "SUCCESS")
        
        # Méthode 1: GCD direct
        self.log("Tentative GCD(m^e - c, n)...", "INFO")
        diff = pow(m, e) - c  # Sans modulo
        g = gcd(diff, n)
        
        if 1 < g < n:
            p = g
            q = n // g
            
            self.log(f"✓ Facteurs trouvés par GCD!", "SUCCESS")
            self.log(f"p = {p}, q = {q}", "SUCCESS")
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                factors=(int(p), int(q)),
                time_elapsed=self._elapsed_time(),
                message="Factorisation via GCD",
                metadata={"method": "gcd_direct"}
            )
        
        # Méthode 2: Essayer avec variations
        self.log("Tentative avec variations...", "INFO")
        
        for k in range(1, 100):
            # Essayer m + k*n
            m_var = m + k * n
            diff_var = pow(m_var, e) - c
            g_var = gcd(diff_var, n)
            
            if 1 < g_var < n:
                p = g_var
                q = n // g_var
                
                self.log(f"✓ Facteurs trouvés avec k={k}!", "SUCCESS")
                
                return AttackResult(
                    status=AttackStatus.SUCCESS,
                    factors=(int(p), int(q)),
                    time_elapsed=self._elapsed_time(),
                    message=f"Factorisation via variation k={k}",
                    metadata={"method": "gcd_variation", "k": k}
                )
            
            if self._check_timeout():
                break
        
        # Méthode 3: Si e petit, calculer d directement (peu probable)
        self.log("Méthode directe inefficace pour ce cas", "WARNING")
        
        return AttackResult(
            status=AttackStatus.FAILED,
            time_elapsed=self._elapsed_time(),
            message="Aucune factorisation trouvée malgré plaintext connu"
        )