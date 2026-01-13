from rich.console import Console
from rich.panel import Panel

console = Console()

def print_banner():
    banner = """
[bold red]
        ,     \\    /      ,        
       / \\    )\\__/(     / \\       
      /   \\  (_\\  /_)   /   \\      
 ____/_____\\__\\@  @/___/_____\\____ 
|             |\\../|              |
|              \\VV/               |
|        TSURUGI FRAMEWORK        |
|_________________________________|
 |    /\\ /      \\\\       \\ /\\    | 
 |  /   V        ))       V   \\  | 
 |/     `       //        '     \\| 
 `              V                '
[/bold red][bold white]      THE OFFENSIVE SWORD OF HIKARI SYSTEM[/bold white]
    """
    console.print(banner)
    console.print(Panel.fit(
        "[yellow]Detect. Verify. Exploit.[/yellow]",
        border_style="red"
    ))

def log_info(msg):
    console.print(f"[blue][*] {msg}[/blue]")

def log_success(msg):
    console.print(f"[green][+] {msg}[/green]")

def log_warning(msg):
    console.print(f"[yellow][!] {msg}[/yellow]")

def log_error(msg):
    console.print(f"[bold red][-] {msg}[/bold red]")
