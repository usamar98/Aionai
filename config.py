import os
from dataclasses import dataclass
from typing import Optional

@dataclass
class Config:
    # Load sensitive data from environment variables
    BOT_TOKEN: str = os.getenv("BOT_TOKEN", "")
    ETHERSCAN_API_KEY: str = os.getenv("ETHERSCAN_API_KEY", "")
    
    # File paths (safe to keep as defaults)
    DATABASE_PATH: str = "data/reports.db"
    SCAM_ADDRESSES_PATH: str = "data/scam_addresses.json"
    RISKY_PATTERNS_PATH: str = "data/risky_patterns.json"
    
    # Risk thresholds (safe to keep as defaults)
    WALLET_RISK_THRESHOLD: float = 0.7
    CONTRACT_RISK_THRESHOLD: float = 0.6
    
    def __post_init__(self):
        """Validate that required environment variables are set"""
        if not self.BOT_TOKEN:
            raise ValueError("BOT_TOKEN environment variable is required")
        if not self.ETHERSCAN_API_KEY:
            raise ValueError("ETHERSCAN_API_KEY environment variable is required")

config = Config()