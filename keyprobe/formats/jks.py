# keyprobe/formats/jks.py
from __future__ import annotations
from typing import Dict, Any

def summarize(data: bytes) -> Dict[str, Any]:
    # Sans mot de passe on ne peut pas introspecter le contenu.
    return {"format": "JKS", "encrypted": True}
