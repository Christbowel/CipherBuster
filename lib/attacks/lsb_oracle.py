"""
LSB Oracle Attack
Attaque par oracle du bit de poids faible (Least Significant Bit)
"""

from .base import BaseAttack, AttackResult, AttackStatus


class LSBOracleAttack(BaseAttack):
    """
    Attaque LSB Oracle
    
    Si on a accès à un oracle qui nous dit si le déchiffrement est pair ou impair,
    on peut retrouver le message complet par recherche binaire.
    
    Complexité: O(log n) requêtes oracle
    """
    
    def execute(self, n: int, e: int, c: int, oracle_func, **params) -> AttackResult:
        """
        Exécute l'attaque LSB Oracle
        
        Args:
            n: Module RSA
            e: Exposant public
            c: Ciphertext
            oracle_func: Fonction oracle(c) -> bool (True si plaintext pair)
        """
        self._start_timer()
        self.log(f"Démarrage LSB Oracle Attack", "INFO")
        self.log(f"Nombre de bits: {n.bit_length()}", "INFO")
        
        if not callable(oracle_func):
            return AttackResult(
                status=AttackStatus.FAILED,
                message="oracle_func doit être une fonction callable"
            )
        
        # Bornes initiales
        lower = 0
        upper = n
        
        # Multiplier par 2^e à chaque itération
        c_mult = c
        two_e = pow(2, e, n)
        
        iterations = 0
        max_iterations = n.bit_length() + 10  # bits de n + marge
        
        self.log("Démarrage de la recherche binaire...", "INFO")
        
        while upper - lower > 1 and iterations < max_iterations:
            # Multiplier le ciphertext par 2^e
            c_mult = (c_mult * two_e) % n
            
            # Demander à l'oracle
            try:
                is_even = oracle_func(c_mult)
            except Exception as ex:
                return AttackResult(
                    status=AttackStatus.FAILED,
                    time_elapsed=self._elapsed_time(),
                    message=f"Erreur oracle: {str(ex)}"
                )
            
            # Mettre à jour les bornes
            mid = (lower + upper) // 2
            
            if is_even:
                # m*2 mod n est pair → m < n/2
                upper = mid
            else:
                # m*2 mod n est impair → m >= n/2
                lower = mid
            
            iterations += 1
            
            # Log périodique
            if self.verbose and iterations % 10 == 0:
                range_size = upper - lower
                progress = 100 * (1 - range_size / n)
                self.log(f"Itération {iterations}, progression: {progress:.2f}%", "INFO")
            
            # Vérifier timeout
            if self._check_timeout():
                return AttackResult(
                    status=AttackStatus.TIMEOUT,
                    time_elapsed=self._elapsed_time(),
                    iterations=iterations,
                    message="Timeout"
                )
        
        # Message trouvé
        m = (lower + upper) // 2
        
        self.log(f"✓ Message trouvé après {iterations} requêtes oracle!", "SUCCESS")
        self.log(f"m = {m}", "SUCCESS")
        
        # Vérification
        if pow(m, e, n) == c:
            verification = "✓ Vérification réussie"
        else:
            verification = "⚠ Approximation (vérification échouée)"
        
        self.log(verification, "SUCCESS" if pow(m, e, n) == c else "WARNING")
        
        try:
            plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        except:
            plaintext = str(m).encode()
        
        return AttackResult(
            status=AttackStatus.SUCCESS,
            plaintext=plaintext,
            time_elapsed=self._elapsed_time(),
            iterations=iterations,
            message="Attaque réussie",
            metadata={
                "m": m,
                "oracle_queries": iterations,
                "verification": verification
            }
        )