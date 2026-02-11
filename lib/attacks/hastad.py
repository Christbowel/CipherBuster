"""
Håstad's Broadcast Attack - NOUVELLE ATTAQUE
"""

from .base import BaseAttack, AttackResult, AttackStatus
from ..utils.math_utils import chinese_remainder_theorem, nth_root, modinv
import math


class HastadBroadcastAttack(BaseAttack):
    """
    Attaque de diffusion de Håstad (Broadcast Attack).
    
    Si le même message m est chiffré avec le même exposant e 
    pour au moins e destinataires différents, on peut retrouver m.
    
    Cas typique: e=3 et on intercepte 3 chiffrés du même message
    """
    
    def execute(self, ciphertexts: list, moduli: list, e: int, **params) -> AttackResult:
        """
        Exécute l'attaque de Håstad
        
        Args:
            ciphertexts: Liste des c_i (au moins e éléments)
            moduli: Liste des n_i (au moins e éléments)
            e: Exposant public commun
        """
        self._start_timer()
        self.log(f"Démarrage Håstad Broadcast Attack avec e={e}", "INFO")
        
        if len(ciphertexts) < e:
            return AttackResult(
                status=AttackStatus.FAILED,
                message=f"Pas assez de chiffrés: {len(ciphertexts)} < {e}"
            )
        
        if len(moduli) < e:
            return AttackResult(
                status=AttackStatus.FAILED,
                message=f"Pas assez de modules: {len(moduli)} < {e}"
            )
        
        c_list = ciphertexts[:e]
        n_list = moduli[:e]
        
        self.log(f"Utilisation de {e} paires (c_i, n_i)", "INFO")
        
        try:
            # Étape 1: Appliquer le Théorème des Restes Chinois
            self.log("Application du CRT...", "INFO")
            m_to_e = chinese_remainder_theorem(c_list, n_list)
            self.log(f"Résultat CRT: m^{e} = {m_to_e}", "INFO")
            
            # Étape 2: Calculer la racine e-ième
            self.log(f"Calcul de la racine {e}-ième...", "INFO")
            m = nth_root(m_to_e, e)
            
            if m is None:
                return AttackResult(
                    status=AttackStatus.FAILED,
                    time_elapsed=self._elapsed_time(),
                    message="Impossible de calculer la racine (m^e >= prod(n_i) ?)"
                )
            
            # Vérification
            if pow(m, e) == m_to_e:
                self.log(f"✓ Message retrouvé!", "SUCCESS")
                self.log(f"m = {m}", "SUCCESS")
                
                
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
                    message="Attaque réussie",
                    metadata={
                        "m": m,
                        "e": e,
                        "num_ciphertexts": e
                    }
                )
            else:
                return AttackResult(
                    status=AttackStatus.FAILED,
                    time_elapsed=self._elapsed_time(),
                    message="Vérification échouée: m^e ≠ résultat CRT"
                )
                
        except Exception as ex:
            self.log(f"Erreur: {str(ex)}", "ERROR")
            return AttackResult(
                status=AttackStatus.FAILED,
                time_elapsed=self._elapsed_time(),
                message=f"Erreur: {str(ex)}"
            )