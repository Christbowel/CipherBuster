"""
Cube Root Attack (e=3 sans modulo)
"""

from .base import BaseAttack, AttackResult, AttackStatus
from ..utils.math_utils import nth_root


class CubeRootAttack(BaseAttack):
    """
    Attaque Cube Root pour e=3
    
    Si e=3 et m^3 < n, alors c = m^3 (pas de modulo)
    On calcule simplement la racine cubique de c.
    
    Très courant en CTF !
    """
    
    def execute(self, c: int, n: int = None, e: int = 3, **params) -> AttackResult:
        """
        Exécute l'attaque Cube Root
        
        Args:
            c: Ciphertext
            n: Module RSA (optionnel)
            e: Exposant (par défaut 3)
        """
        self._start_timer()
        self.log(f"Démarrage Cube Root Attack (e={e})", "INFO")
        
        if e != 3:
            self.log("⚠ Cette attaque est optimisée pour e=3", "WARNING")
        
        # Tentative 1: Racine directe
        self.log("Tentative de racine directe (sans modulo)...", "INFO")
        m = nth_root(c, e)
        
        if m is not None:
            # Vérification
            if pow(m, e) == c:
                self.log(f"✓ Message trouvé! m = {m}", "SUCCESS")
                self.log(f"✓ m^{e} = c (pas de modulo nécessaire)", "SUCCESS")
                
                try:
                    plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                    decoded = plaintext.decode('utf-8', errors='ignore')
                    if decoded:
                        self.log(f"Texte: {decoded}", "SUCCESS")
                except:
                    plaintext = str(m).encode()
                
                return AttackResult(
                    status=AttackStatus.SUCCESS,
                    plaintext=plaintext,
                    time_elapsed=self._elapsed_time(),
                    message="Message trop petit, pas de modulo appliqué",
                    metadata={
                        "m": m,
                        "method": "direct_root",
                        "e": e
                    }
                )
        
        # Tentative 2: Avec ajustements (k*n + c)
        if n is not None:
            self.log("Tentative avec ajustements k*n + c...", "INFO")
            
            for k in range(1, 100):  # Tester quelques valeurs de k
                adjusted_c = c + k * n
                m_candidate = nth_root(adjusted_c, e)
                
                if m_candidate is not None:
                    # Vérifier avec n
                    if pow(m_candidate, e, n) == c:
                        self.log(f"✓ Message trouvé avec k={k}!", "SUCCESS")
                        
                        try:
                            plaintext = m_candidate.to_bytes((m_candidate.bit_length() + 7) // 8, 'big')
                        except:
                            plaintext = str(m_candidate).encode()
                        
                        return AttackResult(
                            status=AttackStatus.SUCCESS,
                            plaintext=plaintext,
                            time_elapsed=self._elapsed_time(),
                            message=f"Trouvé avec k={k}",
                            metadata={
                                "m": m_candidate,
                                "k": k,
                                "method": "adjusted",
                                "e": e
                            }
                        )
                
                if self._check_timeout():
                    break
        
        self.log("Échec: m^e >= n (modulo actif)", "ERROR")
        return AttackResult(
            status=AttackStatus.FAILED,
            time_elapsed=self._elapsed_time(),
            message="Message trop grand, attaque non applicable"
        )