"""
Partial Key Exposure Attack
Exploitation de la connaissance partielle de bits de la clé
"""

from .base import BaseAttack, AttackResult, AttackStatus
import math


class PartialKeyExposureAttack(BaseAttack):
    """
    Attaque par exposition partielle de clé
    
    Si on connaît une partie des bits de p, d, ou d'autres paramètres,
    on peut retrouver le reste par force brute intelligente.
    
    Cas supportés:
    - MSB (Most Significant Bits) de p connus
    - LSB (Least Significant Bits) de p connus
    - Bits du milieu connus
    """
    
    def execute(self, n: int, known_bits: str, position: str = "msb", 
                bit_length: int = None, **params) -> AttackResult:
        """
        Exécute l'attaque de clé partielle
        
        Args:
            n: Module RSA
            known_bits: Bits connus (string binaire, ex: "10110...")
            position: Position des bits ("msb", "lsb", "middle")
            bit_length: Longueur attendue de p en bits
        """
        self._start_timer()
        self.log(f"Démarrage Partial Key Exposure", "INFO")
        self.log(f"Bits connus: {len(known_bits)} bits en position {position}", "INFO")
        
        if bit_length is None:
            bit_length = n.bit_length() // 2
        
        known_int = int(known_bits, 2) if known_bits else 0
        known_len = len(known_bits)
        unknown_bits = bit_length - known_len
        
        self.log(f"Bits à bruteforcer: {unknown_bits}", "INFO")
        
        if unknown_bits > 40:
            self.log(f"⚠ {unknown_bits} bits à tester = 2^{unknown_bits} possibilités!", "WARNING")
            self.log("Cela peut prendre très longtemps...", "WARNING")
        
        max_attempts = min(2 ** unknown_bits, 10000000)  # Limite sécurité
        self.log(f"Max tentatives: {max_attempts}", "INFO")
        
        # Stratégie selon position
        if position == "msb":
            return self._attack_msb(n, known_int, known_len, unknown_bits, max_attempts)
        elif position == "lsb":
            return self._attack_lsb(n, known_int, known_len, unknown_bits, max_attempts)
        else:
            return AttackResult(
                status=AttackStatus.FAILED,
                message=f"Position '{position}' non supportée (msb/lsb uniquement)"
            )
    
    def _attack_msb(self, n: int, known_high: int, known_bits: int, 
                    unknown_bits: int, max_attempts: int) -> AttackResult:
        """Attaque avec MSB connus"""
        self.log("Stratégie MSB: bits de poids fort connus", "INFO")
        
        # p = known_high << unknown_bits | unknown_low
        base = known_high << unknown_bits
        
        for i in range(max_attempts):
            p_candidate = base | i
            
            # Vérifier si p divise n
            if n % p_candidate == 0:
                q = n // p_candidate
                
                # Vérifier que c'est bien un facteur premier
                if p_candidate * q == n and p_candidate > 1 and q > 1:
                    self.log(f"✓ Facteur trouvé après {i+1} tentatives!", "SUCCESS")
                    self.log(f"p = {p_candidate}", "SUCCESS")
                    self.log(f"q = {q}", "SUCCESS")
                    
                    return AttackResult(
                        status=AttackStatus.SUCCESS,
                        factors=(int(p_candidate), int(q)),
                        time_elapsed=self._elapsed_time(),
                        iterations=i + 1,
                        message="Clé retrouvée par MSB",
                        metadata={
                            "known_bits": known_bits,
                            "bruteforced_bits": unknown_bits,
                            "attempts": i + 1
                        }
                    )
            
            # Log périodique
            if self.verbose and i % 10000 == 0 and i > 0:
                progress = 100 * i / max_attempts
                self.log(f"Progression: {progress:.2f}% ({i}/{max_attempts})", "INFO")
            
            # Timeout
            if self._check_timeout():
                return AttackResult(
                    status=AttackStatus.TIMEOUT,
                    time_elapsed=self._elapsed_time(),
                    iterations=i,
                    message="Timeout"
                )
        
        return AttackResult(
            status=AttackStatus.FAILED,
            time_elapsed=self._elapsed_time(),
            iterations=max_attempts,
            message=f"Échec après {max_attempts} tentatives"
        )
    
    def _attack_lsb(self, n: int, known_low: int, known_bits: int,
                    unknown_bits: int, max_attempts: int) -> AttackResult:
        """Attaque avec LSB connus"""
        self.log("Stratégie LSB: bits de poids faible connus", "INFO")
        
        # p = (unknown_high << known_bits) | known_low
        mask = (1 << known_bits) - 1
        
        for i in range(max_attempts):
            p_candidate = (i << known_bits) | known_low
            
            if n % p_candidate == 0:
                q = n // p_candidate
                
                if p_candidate * q == n and p_candidate > 1 and q > 1:
                    self.log(f"✓ Facteur trouvé après {i+1} tentatives!", "SUCCESS")
                    
                    return AttackResult(
                        status=AttackStatus.SUCCESS,
                        factors=(int(p_candidate), int(q)),
                        time_elapsed=self._elapsed_time(),
                        iterations=i + 1,
                        message="Clé retrouvée par LSB",
                        metadata={
                            "known_bits": known_bits,
                            "bruteforced_bits": unknown_bits,
                            "attempts": i + 1
                        }
                    )
            
            if self.verbose and i % 10000 == 0 and i > 0:
                progress = 100 * i / max_attempts
                self.log(f"Progression: {progress:.2f}%", "INFO")
            
            if self._check_timeout():
                return AttackResult(
                    status=AttackStatus.TIMEOUT,
                    time_elapsed=self._elapsed_time(),
                    iterations=i
                )
        
        return AttackResult(
            status=AttackStatus.FAILED,
            time_elapsed=self._elapsed_time(),
            iterations=max_attempts,
            message="Échec"
        )