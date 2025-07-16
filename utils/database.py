import sqlite3
import json
from config import config
import os

async def init_database():
    """Initialize SQLite database for reports"""
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    
    conn = sqlite3.connect(config.DATABASE_PATH)
    cursor = conn.cursor()
    
    # Create reports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT,
            report_type TEXT NOT NULL,
            reported_item TEXT NOT NULL,
            description TEXT,
            timestamp TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()
    
    # Create initial data files if they don't exist
    if not os.path.exists(config.SCAM_ADDRESSES_PATH):
        with open(config.SCAM_ADDRESSES_PATH, 'w') as f:
            json.dump([
                "0x1234567890123456789012345678901234567890",
                "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
            ], f, indent=2)
    
    if not os.path.exists(config.RISKY_PATTERNS_PATH):
        with open(config.RISKY_PATTERNS_PATH, 'w') as f:
            json.dump({
                "high_risk": ["transferFrom", "mint", "blacklist"],
                "medium_risk": ["proxy", "upgradeable", "owner"]
            }, f, indent=2)

async def save_report(report_data: dict):
    """Save user report to database"""
    conn = sqlite3.connect(config.DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO reports (user_id, username, report_type, reported_item, description, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        report_data['user_id'],
        report_data['username'],
        report_data['report_type'],
        report_data['reported_item'],
        report_data['description'],
        report_data['timestamp']
    ))
    
    conn.commit()
    conn.close()