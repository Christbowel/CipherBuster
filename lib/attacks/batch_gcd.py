"""
Batch GCD Attack
Teste le GCD entre plusieurs modules pour trouver des facteurs communs
"""

from .base import BaseAttack, AttackResult, AttackStatus
from ..utils.math_utils import gcd
import math


class BatchGCDAttack(BaseAttack):
    """
    Attaque Batch GCD
    
    Teste tous les GCD entre une liste de modules RSA.
    Si deux modules partagent un facteur premier, GCD(n1, n2) = p
    
    Complexité: O(k²) où k = nombre de modules
    Très efficace contre bases de données de clés mal générées
    """
    
    def execute(self, moduli: list, **params) -> AttackResult:
        """
        Exécute l'attaque Batch GCD
        
        Args:
            moduli: Liste de modules RSA à tester
        """
        self._start_timer()
        self.log(f"Démarrage Batch GCD sur {len(moduli)} modules", "INFO")
        
        if len(moduli) < 2:
            return AttackResult(
                status=AttackStatus.FAILED,
                message="Au moins 2 modules requis"
            )
        
        # Résultats trouvés
        factorizations = {}
        common_factors = []
        
        total_pairs = len(moduli) * (len(moduli) - 1) // 2
        self.log(f"Test de {total_pairs} paires...", "INFO")
        
        tested = 0
        
        # Tester tous les couples
        for i in range(len(moduli)):
            for j in range(i + 1, len(moduli)):
                n1 = moduli[i]
                n2 = moduli[j]
                
                # Calculer GCD
                g = gcd(n1, n2)
                
                if g > 1 and g != n1 and g != n2:
                    # Facteur commun trouvé !
                    self.log(f"✓ Facteur commun trouvé: GCD(n{i}, n{j}) = {g}", "SUCCESS")
                    
                    # Factoriser n1
                    if n1 not in factorizations:
                        q1 = n1 // g
                        factorizations[n1] = (g, q1)
                        self.log(f"  n{i} = {g} × {q1}", "SUCCESS")
                    
                    # Factoriser n2
                    if n2 not in factorizations:
                        q2 = n2 // g
                        factorizations[n2] = (g, q2)
                        self.log(f"  n{j} = {g} × {q2}", "SUCCESS")
                    
                    common_factors.append({
                        "indices": (i, j),
                        "moduli": (n1, n2),
                        "common_factor": g
                    })
                
                tested += 1
                
                # Log périodique
                if self.verbose and tested % 100 == 0:
                    progress = 100 * tested / total_pairs
                    self.log(f"Progression: {progress:.1f}% ({tested}/{total_pairs})", "INFO")
                
                # Vérifier timeout
                if self._check_timeout():
                    return AttackResult(
                        status=AttackStatus.TIMEOUT,
                        time_elapsed=self._elapsed_time(),
                        message=f"Timeout après {tested} paires testées",
                        metadata={
                            "tested": tested,
                            "found": len(factorizations)
                        }
                    )
        
        # Résultat
        if factorizations:
            self.log(f"✓ {len(factorizations)} modules factorisés!", "SUCCESS")
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                time_elapsed=self._elapsed_time(),
                message=f"{len(factorizations)} modules compromis",
                metadata={
                    "factorizations": factorizations,
                    "common_factors": common_factors,
                    "total_tested": tested,
                    "vulnerable_count": len(factorizations)
                }
            )
        else:
            self.log("Aucun facteur commun trouvé", "WARNING")
            return AttackResult(
                status=AttackStatus.FAILED,
                time_elapsed=self._elapsed_time(),
                message="Aucune vulnérabilité détectée",
                metadata={"total_tested": tested}
            )