import threading
from orchestrator.fingerprinter      import PassiveFingerprinter
from orchestrator.spawner            import HoneypotSpawner
from orchestrator.adaptation_engine  import AdaptationEngine
from intel.stix_generator            import STIXGenerator
from config import HONEYPOT_PORTS
from rich.console import Console
from pyfiglet import figlet_format

console = Console()

def banner():
    console.print(figlet_format("AHOS", font="slant"), style="bold red")
    console.print("[bold yellow]Adaptive Honeypot Orchestration System[/bold yellow]")
    console.print("[dim]All Phases Active — Full Pipeline Running[/dim]\n")

if __name__ == "__main__":
    banner()

    spawner = HoneypotSpawner()
    t1 = threading.Thread(target=spawner.start, daemon=True)
    t1.start()

    engine = AdaptationEngine()
    t2 = threading.Thread(target=engine.start, daemon=True)
    t2.start()

    stix = STIXGenerator()
    t3 = threading.Thread(target=stix.start, daemon=True)
    t3.start()

    fp = PassiveFingerprinter(interface="eth0")
    fp.start(ports=HONEYPOT_PORTS)