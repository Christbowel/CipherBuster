"""
Base Attack Class - Architecture pour toutes les attaques RSA
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Any
import time


class AttackStatus(Enum):
    """Status du résultat d'une attaque"""
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    PARTIAL = "partial"


@dataclass
class AttackResult:
    """Résultat standardisé d'une attaque"""
    status: AttackStatus
    message: str = ""
    factors: Optional[tuple] = None
    private_key: Optional[int] = None
    plaintext: Optional[bytes] = None
    time_elapsed: float = 0.0
    iterations: int = 0
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class BaseAttack(ABC):
    """Classe de base pour toutes les attaques RSA"""
    
    def __init__(self, verbose: bool = True, timeout: int = 300):
        self.verbose = verbose
        self.timeout = timeout
        self.name = self.__class__.__name__
        self._start_time = None
    
    @abstractmethod
    def execute(self, **params) -> AttackResult:
        """Exécute l'attaque avec les paramètres donnés"""
        pass
    
    def log(self, message: str, level: str = "INFO", color: str = "white"):
        """Log un message si verbose activé"""
        if self.verbose:
            from rich.console import Console
            console = Console()
            colors = {
                "INFO": "cyan",
                "SUCCESS": "green",
                "WARNING": "yellow",
                "ERROR": "red"
            }
            console.print(f"[{colors.get(level, color)}][{level}] {self.name}: {message}[/{colors.get(level, color)}]")
    
    def _start_timer(self):
        """Démarre le chrono"""
        self._start_time = time.time()
    
    def _elapsed_time(self) -> float:
        """Retourne le temps écoulé"""
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time
    
    def _check_timeout(self) -> bool:
        """Vérifie si timeout dépassé"""
        if self.timeout <= 0:
            return False
        return self._elapsed_time() > self.timeout