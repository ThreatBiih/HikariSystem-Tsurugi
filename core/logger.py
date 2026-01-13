import json
import os
import time
from core.ui import console, log_success

LOOT_DIR = "loot"

if not os.path.exists(LOOT_DIR):
    os.makedirs(LOOT_DIR)

def save_loot(module: str, target_url: str, details: dict):
    """
    Saves confirmed vulnerability details to a JSON file in the loot directory.
    Format: loot/TIMESTAMP_MODULE_DOMAIN.json
    """
    from urllib.parse import urlparse
    domain = urlparse(target_url).netloc.replace(":", "_")
    timestamp = int(time.time())
    
    filename = f"{LOOT_DIR}/{timestamp}_{module}_{domain}.json"
    
    loot_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "module": module,
        "target": target_url,
        "details": details
    }
    
    try:
        with open(filename, 'w') as f:
            json.dump(loot_data, f, indent=4)
        
        console.print(f"  [bold green][+] LOOT SAVED:[/bold green] {filename}")
    except Exception as e:
        console.print(f"[red]Failed to save loot: {e}[/red]")
