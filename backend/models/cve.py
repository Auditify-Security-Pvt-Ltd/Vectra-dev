from __future__ import annotations

from pydantic import BaseModel
from typing import List


class CorrelationRequest(BaseModel):
    assetId: str
    assetUrl: str
    technologies: List[str]   # raw strings: "Apache:2.4.49", "PHP:7.4.3"
    discoveryId: str
