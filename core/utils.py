import os
from typing import List

def load_payloads(filename: str, fallback: List[str] = None) -> List[str]:
    """
    Carrega payloads de um arquivo externo.
    
    Args:
        filename: Nome do arquivo em payloads/
        fallback: Lista de payloads default se arquivo não existir
        
    Returns:
        Lista de payloads
    """
    path = os.path.join("payloads", filename)
    
    if not os.path.exists(path):
        return fallback or []
    
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def validate_url(url: str) -> bool:
    """
    Valida formato básico de URL.
    
    Args:
        url: URL a validar
        
    Returns:
        True se válida, False caso contrário
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return all([parsed.scheme in ['http', 'https'], parsed.netloc])
