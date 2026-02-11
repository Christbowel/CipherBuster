"""
Legacy Wrapper - Attaques compatibles v2.0
"""

from .base import BaseAttack, AttackResult, AttackStatus
import math


class CommonModulusAttack(BaseAttack):
    """Common Modulus Attack"""
    
    def execute(self, n: int, e1: int, e2: int, c1: int, c2: int, **params) -> AttackResult:
        self._start_timer()
        self.log("Exécution Common Modulus Attack", "INFO")
        
        try:
            import gmpy2
            from Crypto.Util.number import long_to_bytes, GCD
            
            def egcd(a, b):
                if a == 0:
                    return (b, 0, 1)
                g, y, x = egcd(b % a, a)
                return (g, x - (b // a) * y, y)
            
            def neg_pow(a, b, n):
                res = int(gmpy2.invert(a, n))
                res = pow(res, b * (-1), n)
                return res
            
            g, a, b = egcd(e1, e2)
            
            c1_mod = neg_pow(c1, a, n) if a < 0 else pow(c1, a, n)
            c2_mod = neg_pow(c2, b, n) if b < 0 else pow(c2, b, n)
            
            ct = c1_mod * c2_mod % n
            m = int(gmpy2.iroot(ct, g)[0])
            
            self.log(f"✓ Message: {m}", "SUCCESS")
            
            try:
                plaintext = long_to_bytes(m)
            except:
                plaintext = str(m).encode()
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                plaintext=plaintext,
                time_elapsed=self._elapsed_time(),
                message="Message retrouvé",
                metadata={"m": m}
            )
        except Exception as ex:
            return AttackResult(
                status=AttackStatus.FAILED,
                time_elapsed=self._elapsed_time(),
                message=f"Erreur: {str(ex)}"
            )


class CommonPrimeAttack(BaseAttack):
    """Common Prime Factor Attack"""
    
    def execute(self, n1: int, n2: int, **params) -> AttackResult:
        self._start_timer()
        self.log("Exécution Common Prime Factor Attack", "INFO")
        
        try:
            p = math.gcd(n1, n2)
            
            if p > 1:
                q1 = n1 // p
                q2 = n2 // p
                
                # Vérifications
                assert p * q1 == n1
                assert p * q2 == n2
                
                self.log(f"✓ Facteur commun: p={p}", "SUCCESS")
                self.log(f"n1 = {p} × {q1}", "SUCCESS")
                self.log(f"n2 = {p} × {q2}", "SUCCESS")
                
                return AttackResult(
                    status=AttackStatus.SUCCESS,
                    factors=(int(p), int(q1)),
                    time_elapsed=self._elapsed_time(),
                    message="Factorisation réussie",
                    metadata={
                        "common_prime": p,
                        "n1_factors": (p, q1),
                        "n2_factors": (p, q2)
                    }
                )
            else:
                return AttackResult(
                    status=AttackStatus.FAILED,
                    time_elapsed=self._elapsed_time(),
                    message="Pas de facteur commun"
                )
        except Exception as ex:
            return AttackResult(
                status=AttackStatus.FAILED,
                time_elapsed=self._elapsed_time(),
                message=f"Erreur: {str(ex)}"
            )


class FactorDBAttack(BaseAttack):
    """FactorDB Lookup Attack"""
    
    def execute(self, n: int, **params) -> AttackResult:
        self._start_timer()
        self.log("Consultation FactorDB...", "INFO")
        
        try:
            from factordb.factordb import FactorDB
            
            f = FactorDB(n)
            f.connect()
            factors = f.get_factor_list()
            
            if len(factors) >= 2:
                p, q = factors[0], factors[1]
                self.log(f"✓ Trouvé dans FactorDB!", "SUCCESS")
                self.log(f"p={p}, q={q}", "SUCCESS")
                
                return AttackResult(
                    status=AttackStatus.SUCCESS,
                    factors=(int(p), int(q)),
                    time_elapsed=self._elapsed_time(),
                    message="Factorisé via FactorDB",
                    metadata={"all_factors": factors}
                )
            else:
                return AttackResult(
                    status=AttackStatus.FAILED,
                    time_elapsed=self._elapsed_time(),
                    message="Non trouvé dans FactorDB"
                )
        except ImportError:
            return AttackResult(
                status=AttackStatus.FAILED,
                time_elapsed=self._elapsed_time(),
                message="factordb non installé: pip install factordb-pycli"
            )
        except Exception as ex:
            return AttackResult(
                status=AttackStatus.FAILED,
                time_elapsed=self._elapsed_time(),
                message=f"Erreur (internet?): {str(ex)}"
            )