"""
Small e with Padding Attack
Détecte et exploite les faiblesses avec petits exposants et padding prévisible
"""

from .base import BaseAttack, AttackResult, AttackStatus
from ..utils.math_utils import nth_root


class SmallEPaddingAttack(BaseAttack):
    """
    Attaque sur petit e avec padding
    
    Détecte automatiquement:
    - e=3 sans padding suffisant
    - Padding prévisible
    - Message court
    """
    
    def execute(self, n: int, e: int, c: int, **params) -> AttackResult:
        """
        Exécute l'attaque Small e + Padding
        
        Args:
            n: Module RSA
            e: Exposant public
            c: Ciphertext
        """
        self._start_timer()
        self.log(f"Analyse de e={e} avec n de {n.bit_length()} bits", "INFO")
        
        if e > 65537:
            return AttackResult(
                status=AttackStatus.FAILED,
                message=f"e={e} n'est pas considéré comme petit"
            )
        
        self.log(f"✓ e={e} est petit, tentative d'attaque...", "INFO")
        

        self.log("Stratégie 1: Racine directe...", "INFO")
        m = nth_root(c, e)
        
        if m is not None and pow(m, e) == c:
            self.log(f"✓ SUCCÈS (racine directe)! m = {m}", "SUCCESS")
            
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
                message="Message sans padding suffisant",
                metadata={
                    "m": m,
                    "attack_type": "direct_root",
                    "e": e
                }
            )
        
        self.log("Stratégie 2: Avec ajustements k*n...", "INFO")
        
        max_k = min(1000, 2 ** e)  
        
        for k in range(1, max_k):
            adjusted = c + k * n
            m_candidate = nth_root(adjusted, e)
            
            if m_candidate is not None:
                if pow(m_candidate, e, n) == c:
                    self.log(f"✓ SUCCÈS avec k={k}! m = {m_candidate}", "SUCCESS")
                    
                    try:
                        plaintext = m_candidate.to_bytes((m_candidate.bit_length() + 7) // 8, 'big')
                    except:
                        plaintext = str(m_candidate).encode()
                    
                    return AttackResult(
                        status=AttackStatus.SUCCESS,
                        plaintext=plaintext,
                        time_elapsed=self._elapsed_time(),
                        message=f"Trouvé avec offset k={k}",
                        metadata={
                            "m": m_candidate,
                            "k": k,
                            "attack_type": "adjusted",
                            "e": e
                        }
                    )
            
            if self.verbose and k % 100 == 0:
                self.log(f"Test k={k}/{max_k}...", "INFO")
            
            if self._check_timeout():
                return AttackResult(
                    status=AttackStatus.TIMEOUT,
                    time_elapsed=self._elapsed_time(),
                    message=f"Timeout après k={k}"
                )
        
        if 'ciphertexts' in params and 'moduli' in params:
            self.log("Stratégie 3: Tentative Håstad Broadcast...", "INFO")
            # Déléguer à HastadAttack
            from .hastad import HastadBroadcastAttack
            hastad = HastadBroadcastAttack(verbose=self.verbose)
            return hastad.execute(
                ciphertexts=params['ciphertexts'],
                moduli=params['moduli'],
                e=e
            )
        
        self.log("Échec: aucune stratégie n'a fonctionné", "ERROR")
        return AttackResult(
            status=AttackStatus.FAILED,
            time_elapsed=self._elapsed_time(),
            message="Padding suffisant ou message trop grand"
        )