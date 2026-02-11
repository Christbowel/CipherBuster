"""
Module d'attaques RSA - CipherBuster v2.0
19 attaques disponibles
"""

from .base import BaseAttack, AttackResult, AttackStatus

# Attaques de factorisation
from .fermat import FermatAttack
from .fermat_variants import FermatVariantsAttack
from .pollard_rho import PollardRhoAttack
from .pollard_p1 import PollardP1Attack
from .williams_p1 import WilliamsP1Attack

# Attaques sur exposants
from .wiener import WienerAttack
from .hastad import HastadBroadcastAttack
from .cube_root import CubeRootAttack
from .small_e_padding import SmallEPaddingAttack

# Attaques multi-clés
from .franklin_reiter import FranklinReiterAttack
from .legacy_wrapper import CommonModulusAttack, CommonPrimeAttack, FactorDBAttack
from .batch_gcd import BatchGCDAttack

# Attaques avancées
from .lsb_oracle import LSBOracleAttack
from .partial_key import PartialKeyExposureAttack
from .multiprime import MultiPrimeRSAAttack
from .known_plaintext import KnownPlaintextAttack
from .smooth_number import SmoothNumberAttack

__all__ = [
    'BaseAttack', 'AttackResult', 'AttackStatus',
    # Factorisation
    'FermatAttack', 'FermatVariantsAttack',
    'PollardRhoAttack', 'PollardP1Attack', 'WilliamsP1Attack',
    # Exposants
    'WienerAttack', 'HastadBroadcastAttack',
    'CubeRootAttack', 'SmallEPaddingAttack',
    # Multi-clés
    'FranklinReiterAttack', 'CommonModulusAttack',
    'CommonPrimeAttack', 'FactorDBAttack', 'BatchGCDAttack',
    # Avancées
    'LSBOracleAttack', 'PartialKeyExposureAttack',
    'MultiPrimeRSAAttack', 'KnownPlaintextAttack', 'SmoothNumberAttack'
]