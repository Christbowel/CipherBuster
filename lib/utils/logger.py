"""
Système de logging professionnel pour CipherBuster
"""

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.table import Table
import time


class CipherLogger:
    """Logger avec Rich pour une belle interface"""
    
    def __init__(self):
        self.console = Console()
    
    def info(self, message: str):
        self.console.print(f"[cyan][INFO][/cyan] {message}")
    
    def success(self, message: str):
        self.console.print(f"[green]✓[/green] {message}")
    
    def warning(self, message: str):
        self.console.print(f"[yellow]⚠[/yellow] {message}")
    
    def error(self, message: str):
        self.console.print(f"[red]✗[/red] {message}")
    
    def banner(self, text: str):
        self.console.print(Panel(text, style="bold cyan"))
    
    def table_result(self, title: str, data: dict):
        """Affiche un résultat sous forme de tableau"""
        table = Table(title=title, show_header=False)
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="white")
        
        for key, value in data.items():
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def progress_bar(self, description: str):
        """Retourne une barre de progression"""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        )


# Instance globale
logger = CipherLogger()