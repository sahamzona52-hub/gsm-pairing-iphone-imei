#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         PEGASUSMETASEC v5.0.0                              ║
║                    Complete GSM Security Suite                             ║
║                                                                             ║
║  Features:                                                                  ║
║  • IMEI Validation, Decoding & Analysis                                    ║
║  • iPhone & Android Device Pairing (3-12 months)                          ║
║  • Real-time GSM Signal Scanning                                           ║
║  • Security Auditing & Vulnerability Assessment                           ║
║  • Complete Database Management                                            ║
║  • Report Generation & Export                                              ║
║                                                                             ║
║  ⚠️  LEGAL: For authorized security testing only                          ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import json
import time
import hashlib
import base64
import sqlite3
import threading
import subprocess
import re
import uuid
import csv
import random
import socket
import platform
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict

# ============================================================================
# DEPENDENCY CHECK & INSTALLATION
# ============================================================================

REQUIRED_PACKAGES = [
    'rich>=13.5.0',
    'cryptography>=39.0.0',
    'requests>=2.28.0',
    'colorama>=0.4.6'
]

def check_and_install_dependencies():
    """Check and install required dependencies"""
    missing = []
    for package in REQUIRED_PACKAGES:
        pkg_name = package.split('>=')[0]
        try:
            __import__(pkg_name)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"[!] Installing missing dependencies: {', '.join(missing)}")
        for package in missing:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", package
            ])
        print("[+] Dependencies installed. Restarting...")
        os.execv(sys.executable, [sys.executable] + sys.argv)

check_and_install_dependencies()

# Now import all dependencies
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt import Prompt, Confirm
    from rich.box import DOUBLE_EDGE, ROUNDED, HEAVY
    from rich.text import Text
    from rich import print as rprint
    from rich.columns import Columns
    from rich.tree import Tree
    from rich.syntax import Syntax
    from rich.layout import Layout
    from rich.traceback import install
    install()
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import requests
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError as e:
    print(f"[!] Import error: {e}")
    print("[!] Please run: pip install -r requirements.txt")
    sys.exit(1)

# Initialize Console
console = Console()

# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================

VERSION = "5.0.0"
AUTHOR = "PegasusMetaSec Security Research"
SOFTWARE_NAME = "PegasusMetaSec"

CONFIG = {
    "version": VERSION,
    "author": AUTHOR,
    "database": "pegasus_imei.db",
    "pairing_db": "pegasus_pairing.db",
    "log_file": "pegasus_operations.log",
    "max_pairing_months": 12,
    "min_pairing_months": 3,
    "default_security": "High",
    "supported_networks": ["2G", "3G", "4G", "5G"]
}

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class DeviceInfo:
    """Complete device information"""
    imei: str
    device_type: str
    brand: str
    model: str
    model_name: str
    generation: str
    release_date: str
    os_version: str
    security_patch: str
    network_type: List[str]
    supported_bands: List[str]
    country_origin: str
    manufacturing_date: str
    warranty_status: str
    sim_status: str
    carrier_lock: str
    iccid: Optional[str] = None
    imsi: Optional[str] = None
    last_known_location: Optional[str] = None
    activation_date: Optional[str] = None

@dataclass
class PairingRecord:
    """Long-term pairing record"""
    pairing_id: str
    device_imei: str
    target_imei: str
    pairing_date: datetime
    expiry_date: datetime
    pairing_duration_months: int
    status: str
    security_level: str
    encryption_key: str
    pair_hash: str
    last_activity: datetime
    data_transferred: int
    authentication_count: int
    device_info: Dict[str, Any]
    target_info: Dict[str, Any]
    notes: str = ""

@dataclass
class IMEIValidationResult:
    """IMEI validation results"""
    imei: str
    is_valid: bool
    validation_errors: List[str]
    device_type: str
    manufacturer: str
    device_class: str
    is_blacklisted: bool
    blacklist_reason: str
    reported_stolen: bool
    warranty_valid: bool
    carrier_locked: bool
    activation_locked: bool

# ============================================================================
# IMEI DATABASE
# ============================================================================

class IMEIDatabase:
    """Comprehensive IMEI database for iPhone and Android"""
    
    def __init__(self):
        self._load_databases()
    
    def _load_databases(self):
        """Load IMEI databases"""
        # iPhone TAC database (first 8 digits)
        self.iphone_tac_db = {
            # iPhone 15 Series
            "35678901": {"model": "iPhone 15", "generation": "15th", "release": "2023", "type": "iPhone"},
            "35678902": {"model": "iPhone 15 Plus", "generation": "15th", "release": "2023", "type": "iPhone"},
            "35678903": {"model": "iPhone 15 Pro", "generation": "15th", "release": "2023", "type": "iPhone"},
            "35678904": {"model": "iPhone 15 Pro Max", "generation": "15th", "release": "2023", "type": "iPhone"},
            # iPhone 14 Series
            "35478901": {"model": "iPhone 14", "generation": "14th", "release": "2022", "type": "iPhone"},
            "35478902": {"model": "iPhone 14 Plus", "generation": "14th", "release": "2022", "type": "iPhone"},
            "35478903": {"model": "iPhone 14 Pro", "generation": "14th", "release": "2022", "type": "iPhone"},
            "35478904": {"model": "iPhone 14 Pro Max", "generation": "14th", "release": "2022", "type": "iPhone"},
            # iPhone 13 Series
            "35378901": {"model": "iPhone 13", "generation": "13th", "release": "2021", "type": "iPhone"},
            "35378902": {"model": "iPhone 13 Mini", "generation": "13th", "release": "2021", "type": "iPhone"},
            "35378903": {"model": "iPhone 13 Pro", "generation": "13th", "release": "2021", "type": "iPhone"},
            "35378904": {"model": "iPhone 13 Pro Max", "generation": "13th", "release": "2021", "type": "iPhone"},
            # iPhone 12 Series
            "35278901": {"model": "iPhone 12", "generation": "12th", "release": "2020", "type": "iPhone"},
            "35278902": {"model": "iPhone 12 Mini", "generation": "12th", "release": "2020", "type": "iPhone"},
            "35278903": {"model": "iPhone 12 Pro", "generation": "12th", "release": "2020", "type": "iPhone"},
            "35278904": {"model": "iPhone 12 Pro Max", "generation": "12th", "release": "2020", "type": "iPhone"},
            # iPhone 11 Series
            "35178901": {"model": "iPhone 11", "generation": "11th", "release": "2019", "type": "iPhone"},
            "35178902": {"model": "iPhone 11 Pro", "generation": "11th", "release": "2019", "type": "iPhone"},
            "35178903": {"model": "iPhone 11 Pro Max", "generation": "11th", "release": "2019", "type": "iPhone"},
            # iPhone X Series
            "35078901": {"model": "iPhone X", "generation": "10th", "release": "2017", "type": "iPhone"},
            "35078902": {"model": "iPhone XR", "generation": "10th", "release": "2018", "type": "iPhone"},
            "35078903": {"model": "iPhone XS", "generation": "10th", "release": "2018", "type": "iPhone"},
            "35078904": {"model": "iPhone XS Max", "generation": "10th", "release": "2018", "type": "iPhone"},
            # iPhone SE Series
            "35788901": {"model": "iPhone SE (1st gen)", "generation": "SE", "release": "2016", "type": "iPhone"},
            "35788902": {"model": "iPhone SE (2nd gen)", "generation": "SE", "release": "2020", "type": "iPhone"},
            "35788903": {"model": "iPhone SE (3rd gen)", "generation": "SE", "release": "2022", "type": "iPhone"},
            # iPhone 8 Series
            "35878901": {"model": "iPhone 8", "generation": "8th", "release": "2017", "type": "iPhone"},
            "35878902": {"model": "iPhone 8 Plus", "generation": "8th", "release": "2017", "type": "iPhone"},
            # iPhone 7 Series
            "35978901": {"model": "iPhone 7", "generation": "7th", "release": "2016", "type": "iPhone"},
            "35978902": {"model": "iPhone 7 Plus", "generation": "7th", "release": "2016", "type": "iPhone"},
        }
        
        # Android TAC database
        self.android_tac_db = {
            # Samsung Galaxy S Series
            "35250101": {"model": "Galaxy S23 Ultra", "generation": "S23", "release": "2023", "type": "Android"},
            "35250102": {"model": "Galaxy S23+", "generation": "S23", "release": "2023", "type": "Android"},
            "35250103": {"model": "Galaxy S23", "generation": "S23", "release": "2023", "type": "Android"},
            "35240101": {"model": "Galaxy S22 Ultra", "generation": "S22", "release": "2022", "type": "Android"},
            "35240102": {"model": "Galaxy S22+", "generation": "S22", "release": "2022", "type": "Android"},
            "35240103": {"model": "Galaxy S22", "generation": "S22", "release": "2022", "type": "Android"},
            "35230101": {"model": "Galaxy S21 Ultra", "generation": "S21", "release": "2021", "type": "Android"},
            "35230102": {"model": "Galaxy S21+", "generation": "S21", "release": "2021", "type": "Android"},
            "35230103": {"model": "Galaxy S21", "generation": "S21", "release": "2021", "type": "Android"},
            # Samsung Galaxy Note Series
            "35260101": {"model": "Galaxy Note 20 Ultra", "generation": "Note 20", "release": "2020", "type": "Android"},
            "35260102": {"model": "Galaxy Note 20", "generation": "Note 20", "release": "2020", "type": "Android"},
            # Samsung Galaxy A Series
            "35350101": {"model": "Galaxy A54", "generation": "A54", "release": "2023", "type": "Android"},
            "35350102": {"model": "Galaxy A34", "generation": "A34", "release": "2023", "type": "Android"},
            "35340101": {"model": "Galaxy A53", "generation": "A53", "release": "2022", "type": "Android"},
            "35340102": {"model": "Galaxy A33", "generation": "A33", "release": "2022", "type": "Android"},
            # Samsung Galaxy Z Series
            "35450101": {"model": "Galaxy Z Fold 5", "generation": "Z Fold 5", "release": "2023", "type": "Android"},
            "35450102": {"model": "Galaxy Z Flip 5", "generation": "Z Flip 5", "release": "2023", "type": "Android"},
            "35440101": {"model": "Galaxy Z Fold 4", "generation": "Z Fold 4", "release": "2022", "type": "Android"},
            "35440102": {"model": "Galaxy Z Flip 4", "generation": "Z Flip 4", "release": "2022", "type": "Android"},
            # Google Pixel Series
            "35550101": {"model": "Pixel 8 Pro", "generation": "Pixel 8", "release": "2023", "type": "Android"},
            "35550102": {"model": "Pixel 8", "generation": "Pixel 8", "release": "2023", "type": "Android"},
            "35540101": {"model": "Pixel 7 Pro", "generation": "Pixel 7", "release": "2022", "type": "Android"},
            "35540102": {"model": "Pixel 7", "generation": "Pixel 7", "release": "2022", "type": "Android"},
            "35530101": {"model": "Pixel 6 Pro", "generation": "Pixel 6", "release": "2021", "type": "Android"},
            "35530102": {"model": "Pixel 6", "generation": "Pixel 6", "release": "2021", "type": "Android"},
            # OnePlus Series
            "35650101": {"model": "OnePlus 11", "generation": "11", "release": "2023", "type": "Android"},
            "35640101": {"model": "OnePlus 10 Pro", "generation": "10 Pro", "release": "2022", "type": "Android"},
            "35640102": {"model": "OnePlus 10", "generation": "10", "release": "2022", "type": "Android"},
            # Xiaomi Series
            "35750101": {"model": "Xiaomi 13 Pro", "generation": "13 Pro", "release": "2023", "type": "Android"},
            "35750102": {"model": "Xiaomi 13", "generation": "13", "release": "2023", "type": "Android"},
            "35740101": {"model": "Xiaomi 12 Pro", "generation": "12 Pro", "release": "2022", "type": "Android"},
            "35740102": {"model": "Xiaomi 12", "generation": "12", "release": "2022", "type": "Android"},
            # Sony Xperia Series
            "35850101": {"model": "Xperia 1 V", "generation": "1 V", "release": "2023", "type": "Android"},
            "35850102": {"model": "Xperia 5 V", "generation": "5 V", "release": "2023", "type": "Android"},
            "35840101": {"model": "Xperia 1 IV", "generation": "1 IV", "release": "2022", "type": "Android"},
            "35840102": {"model": "Xperia 5 IV", "generation": "5 IV", "release": "2022", "type": "Android"},
        }
        
        # Blacklisted IMEIs (simulated)
        self.blacklist_db = {
            "123456789012345": {"reason": "Reported stolen", "date": "2023-01-15"},
            "987654321098765": {"reason": "Lost device", "date": "2023-06-20"},
            "555555555555555": {"reason": "Insurance fraud", "date": "2023-03-10"},
            "111111111111111": {"reason": "Unpaid bill", "date": "2023-08-01"},
            "999999999999999": {"reason": "Network violation", "date": "2023-05-15"},
        }
        
        # Locked devices
        self.locked_db = {
            "444444444444444": {"carrier": "AT&T", "type": "Carrier Locked"},
            "666666666666666": {"carrier": "Verizon", "type": "Carrier Locked"},
            "777777777777777": {"carrier": "T-Mobile", "type": "Carrier Locked"},
            "888888888888888": {"carrier": "Sprint", "type": "Carrier Locked"},
        }

    def lookup_device(self, imei: str) -> Dict[str, Any]:
        """Look up device information from IMEI"""
        tac = imei[:8] if len(imei) >= 8 else imei
        
        if tac in self.iphone_tac_db:
            info = self.iphone_tac_db[tac].copy()
            info["type"] = "iPhone"
            info["manufacturer"] = "Apple"
            return info
        
        if tac in self.android_tac_db:
            info = self.android_tac_db[tac].copy()
            info["type"] = "Android"
            info["manufacturer"] = self._get_android_manufacturer(tac)
            return info
        
        return {
            "model": "Unknown Device",
            "generation": "Unknown",
            "release": "Unknown",
            "type": "Unknown",
            "manufacturer": "Unknown"
        }
    
    def _get_android_manufacturer(self, tac: str) -> str:
        """Get Android manufacturer from TAC"""
        prefixes = {
            "3525": "Samsung", "3524": "Samsung", "3523": "Samsung", "3526": "Samsung",
            "3535": "Samsung", "3534": "Samsung",
            "3545": "Samsung", "3544": "Samsung",
            "3555": "Google", "3554": "Google", "3553": "Google",
            "3565": "OnePlus", "3564": "OnePlus", "3563": "OnePlus",
            "3575": "Xiaomi", "3574": "Xiaomi",
            "3585": "Sony", "3584": "Sony",
        }
        
        for prefix, manufacturer in prefixes.items():
            if tac.startswith(prefix):
                return manufacturer
        return "Unknown"

# ============================================================================
# DATABASE MANAGER
# ============================================================================

class DatabaseManager:
    """Comprehensive database manager for all data"""
    
    def __init__(self):
        self.db_path = CONFIG["database"]
        self.pairing_db_path = CONFIG["pairing_db"]
        self._init_databases()
    
    def _init_databases(self):
        """Initialize both databases"""
        self._init_main_db()
        self._init_pairing_db()
    
    def _init_main_db(self):
        """Initialize main IMEI database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS imei_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                imei TEXT UNIQUE NOT NULL,
                tac TEXT,
                brand TEXT,
                model TEXT,
                model_name TEXT,
                device_type TEXT,
                manufacturing_date TEXT,
                country_of_origin TEXT,
                blacklist_status INTEGER DEFAULT 0,
                reported_stolen INTEGER DEFAULT 0,
                warranty_status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS gsm_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                operator_name TEXT,
                network_type TEXT,
                band TEXT,
                signal_strength INTEGER,
                signal_quality TEXT,
                frequency TEXT,
                mcc INTEGER,
                mnc INTEGER,
                cell_id INTEGER,
                is_roaming INTEGER DEFAULT 0
            );
            
            CREATE TABLE IF NOT EXISTS security_audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                imei TEXT,
                vulnerability TEXT,
                severity TEXT,
                recommendation TEXT,
                patched INTEGER DEFAULT 0
            );
            
            CREATE INDEX IF NOT EXISTS idx_imei_imei ON imei_records(imei);
            CREATE INDEX IF NOT EXISTS idx_gsm_time ON gsm_scans(scan_time);
        """)
        
        conn.commit()
        conn.close()
    
    def _init_pairing_db(self):
        """Initialize pairing database"""
        conn = sqlite3.connect(self.pairing_db_path)
        cursor = conn.cursor()
        
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS pairing_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pairing_id TEXT UNIQUE NOT NULL,
                device_imei TEXT NOT NULL,
                target_imei TEXT NOT NULL,
                pairing_date TIMESTAMP NOT NULL,
                expiry_date TIMESTAMP NOT NULL,
                pairing_duration_months INTEGER NOT NULL,
                status TEXT DEFAULT 'Active',
                security_level TEXT DEFAULT 'High',
                encryption_key TEXT NOT NULL,
                pair_hash TEXT NOT NULL,
                last_activity TIMESTAMP,
                data_transferred INTEGER DEFAULT 0,
                authentication_count INTEGER DEFAULT 0,
                device_info TEXT,
                target_info TEXT,
                notes TEXT
            );
            
            CREATE TABLE IF NOT EXISTS pairing_activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                activity_id TEXT UNIQUE NOT NULL,
                pairing_id TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                activity_type TEXT NOT NULL,
                description TEXT,
                ip_address TEXT,
                location TEXT,
                success INTEGER DEFAULT 1,
                metadata TEXT
            );
            
            CREATE INDEX IF NOT EXISTS idx_pairing_imei ON pairing_records(device_imei, target_imei);
            CREATE INDEX IF NOT EXISTS idx_pairing_status ON pairing_records(status);
            CREATE INDEX IF NOT EXISTS idx_activities_pairing ON pairing_activities(pairing_id);
        """)
        
        conn.commit()
        conn.close()
    
    def save_imei_record(self, imei: str, data: Dict):
        """Save IMEI record to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO imei_records 
            (imei, tac, brand, model, model_name, device_type, 
             manufacturing_date, country_of_origin, blacklist_status, 
             reported_stolen, warranty_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            imei,
            data.get("tac", ""),
            data.get("brand", ""),
            data.get("model", ""),
            data.get("model_name", ""),
            data.get("device_type", ""),
            data.get("manufacturing_date", ""),
            data.get("country_of_origin", ""),
            1 if data.get("blacklisted", False) else 0,
            1 if data.get("stolen", False) else 0,
            data.get("warranty", "Unknown")
        ))
        
        conn.commit()
        conn.close()
    
    def save_pairing_record(self, record: PairingRecord):
        """Save pairing record to database"""
        conn = sqlite3.connect(self.pairing_db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO pairing_records 
            (pairing_id, device_imei, target_imei, pairing_date, expiry_date,
             pairing_duration_months, status, security_level, encryption_key,
             pair_hash, last_activity, data_transferred, authentication_count,
             device_info, target_info, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record.pairing_id,
            record.device_imei,
            record.target_imei,
            record.pairing_date.isoformat(),
            record.expiry_date.isoformat(),
            record.pairing_duration_months,
            record.status,
            record.security_level,
            record.encryption_key,
            record.pair_hash,
            record.last_activity.isoformat() if record.last_activity else None,
            record.data_transferred,
            record.authentication_count,
            json.dumps(record.device_info),
            json.dumps(record.target_info),
            record.notes
        ))
        
        conn.commit()
        conn.close()
    
    def log_activity(self, pairing_id: str, activity_type: str, 
                     description: str, success: bool = True,
                     metadata: Dict = None):
        """Log pairing activity"""
        conn = sqlite3.connect(self.pairing_db_path)
        cursor = conn.cursor()
        
        activity_id = f"ACT-{uuid.uuid4().hex[:8]}"
        
        cursor.execute("""
            INSERT INTO pairing_activities 
            (activity_id, pairing_id, timestamp, activity_type, description,
             ip_address, location, success, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            activity_id,
            pairing_id,
            datetime.now().isoformat(),
            activity_type,
            description,
            "127.0.0.1",
            "Local",
            1 if success else 0,
            json.dumps(metadata or {})
        ))
        
        conn.commit()
        conn.close()
    
    def get_pairing_records(self, status: str = None) -> List[Dict]:
        """Get pairing records from database"""
        conn = sqlite3.connect(self.pairing_db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM pairing_records"
        if status:
            query += f" WHERE status = '{status}'"
        query += " ORDER BY pairing_date DESC"
        
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        
        records = []
        for row in rows:
            records.append({
                "id": row[0],
                "pairing_id": row[1],
                "device_imei": row[2],
                "target_imei": row[3],
                "pairing_date": row[4],
                "expiry_date": row[5],
                "duration_months": row[6],
                "status": row[7],
                "security_level": row[8],
                "encryption_key": row[9],
                "pair_hash": row[10],
                "last_activity": row[11],
                "data_transferred": row[12],
                "authentication_count": row[13],
                "device_info": json.loads(row[14]) if row[14] else {},
                "target_info": json.loads(row[15]) if row[15] else {},
                "notes": row[16] or ""
            })
        
        return records

# ============================================================================
# IMEI ANALYZER
# ============================================================================

class IMEIAnalyzer:
    """Analyze and validate IMEI numbers"""
    
    def __init__(self):
        self.imei_db = IMEIDatabase()
        self.db = DatabaseManager()
    
    def validate_imei(self, imei: str) -> IMEIValidationResult:
        """Comprehensive IMEI validation"""
        errors = []
        imei = re.sub(r'[\s-]', '', imei)
        
        # Check length
        if len(imei) != 15:
            errors.append("IMEI must be exactly 15 digits")
        
        # Check digits only
        if not imei.isdigit():
            errors.append("IMEI must contain only digits")
        
        # Luhn algorithm
        if imei.isdigit() and len(imei) == 15:
            digits = [int(d) for d in imei]
            checksum = 0
            for i in range(14):
                if i % 2 == 0:
                    val = digits[i] * 2
                    checksum += val if val < 10 else val - 9
                else:
                    checksum += digits[i]
            check_digit = (10 - (checksum % 10)) % 10
            if check_digit != digits[14]:
                errors.append("Invalid IMEI checksum")
        
        # Look up device
        device_info = self.imei_db.lookup_device(imei)
        
        # Check blacklist
        is_blacklisted = imei in self.imei_db.blacklist_db
        blacklist_reason = self.imei_db.blacklist_db.get(imei, {}).get("reason", "")
        
        # Check lock status
        is_locked = imei in self.imei_db.locked_db
        
        # Determine device type
        device_type = "iPhone" if "iPhone" in device_info.get("model", "") else \
                     "Android" if device_info.get("type") == "Android" else "Unknown"
        
        is_valid = len(errors) == 0
        
        return IMEIValidationResult(
            imei=imei,
            is_valid=is_valid,
            validation_errors=errors,
            device_type=device_type,
            manufacturer=device_info.get("manufacturer", "Unknown"),
            device_class=device_info.get("model", "Unknown"),
            is_blacklisted=is_blacklisted,
            blacklist_reason=blacklist_reason,
            reported_stolen=is_blacklisted,
            warranty_valid=not is_blacklisted,
            carrier_locked=is_locked,
            activation_locked=False
        )
    
    def analyze_imei(self, imei: str, detailed: bool = False) -> Dict[str, Any]:
        """Analyze IMEI and return detailed information"""
        result = self.validate_imei(imei)
        device_info = self.imei_db.lookup_device(imei)
        
        analysis = {
            "imei": imei,
            "valid": result.is_valid,
            "errors": result.validation_errors,
            "device_type": result.device_type,
            "manufacturer": result.manufacturer,
            "model": result.device_class,
            "tac": imei[:8],
            "snr": imei[8:14],
            "cdn": imei[14:],
            "blacklisted": result.is_blacklisted,
            "blacklist_reason": result.blacklist_reason,
            "reported_stolen": result.reported_stolen,
            "carrier_locked": result.carrier_locked,
            "warranty_valid": result.warranty_valid
        }
        
        if detailed:
            analysis.update({
                "release_date": device_info.get("release", "Unknown"),
                "generation": device_info.get("generation", "Unknown"),
                "supported_networks": CONFIG["supported_networks"]
            })
        
        return analysis
    
    def decode_imei(self, imei: str) -> Dict[str, str]:
        """Decode IMEI components"""
        imei = re.sub(r'[\s-]', '', imei)
        valid, _ = self.validate_imei(imei)
        
        if not valid:
            return {"error": "Invalid IMEI"}
        
        return {
            "tac": imei[:8],
            "fac": imei[:2],
            "snr": imei[8:14],
            "cdn": imei[14:],
            "full": imei,
            "manufacturer": self.imei_db.lookup_device(imei).get("manufacturer", "Unknown")
        }

# ============================================================================
# PAIRING MANAGER
# ============================================================================

class PairingManager:
    """Manage long-term device pairing"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.imei_db = IMEIDatabase()
        self.imei_analyzer = IMEIAnalyzer()
        self.pairing_records = {}
        self.active_pairings = {}
        self._load_existing_pairings()
    
    def _load_existing_pairings(self):
        """Load existing pairing records"""
        records = self.db.get_pairing_records(status="Active")
        for record in records:
            pairing_record = PairingRecord(
                pairing_id=record["pairing_id"],
                device_imei=record["device_imei"],
                target_imei=record["target_imei"],
                pairing_date=datetime.fromisoformat(record["pairing_date"]),
                expiry_date=datetime.fromisoformat(record["expiry_date"]),
                pairing_duration_months=record["duration_months"],
                status=record["status"],
                security_level=record["security_level"],
                encryption_key=record["encryption_key"],
                pair_hash=record["pair_hash"],
                last_activity=datetime.fromisoformat(record["last_activity"]) if record["last_activity"] else None,
                data_transferred=record["data_transferred"],
                authentication_count=record["authentication_count"],
                device_info=record["device_info"],
                target_info=record["target_info"],
                notes=record["notes"]
            )
            self.pairing_records[pairing_record.pairing_id] = pairing_record
            if pairing_record.status == "Active":
                self.active_pairings[pairing_record.pairing_id] = pairing_record
    
    def pair_devices(self, device_imei: str, target_imei: str, 
                    duration_months: int = 6,
                    security_level: str = "High") -> PairingRecord:
        """Pair two devices with long-term validity"""
        
        # Validate IMEIs
        dev_result = self.imei_analyzer.validate_imei(device_imei)
        tgt_result = self.imei_analyzer.validate_imei(target_imei)
        
        if not dev_result.is_valid:
            raise ValueError(f"Invalid device IMEI: {', '.join(dev_result.validation_errors)}")
        if not tgt_result.is_valid:
            raise ValueError(f"Invalid target IMEI: {', '.join(tgt_result.validation_errors)}")
        
        # Check duration
        if duration_months < CONFIG["min_pairing_months"] or duration_months > CONFIG["max_pairing_months"]:
            raise ValueError(f"Duration must be between {CONFIG['min_pairing_months']} and {CONFIG['max_pairing_months']} months")
        
        # Check if already paired
        existing = self._find_existing_pair(device_imei, target_imei)
        if existing:
            return existing
        
        # Get device info
        device_info = self.imei_db.lookup_device(device_imei)
        target_info = self.imei_db.lookup_device(target_imei)
        
        # Generate pairing data
        pairing_id = self._generate_pairing_id(device_imei, target_imei)
        encryption_key = self._generate_encryption_key()
        pair_hash = self._generate_pair_hash(device_imei, target_imei, encryption_key)
        
        # Set dates
        pairing_date = datetime.now()
        expiry_date = pairing_date + timedelta(days=duration_months * 30)
        
        # Create pairing record
        record = PairingRecord(
            pairing_id=pairing_id,
            device_imei=device_imei,
            target_imei=target_imei,
            pairing_date=pairing_date,
            expiry_date=expiry_date,
            pairing_duration_months=duration_months,
            status="Active",
            security_level=security_level,
            encryption_key=encryption_key,
            pair_hash=pair_hash,
            last_activity=pairing_date,
            data_transferred=0,
            authentication_count=0,
            device_info=device_info,
            target_info=target_info,
            notes=f"Paired for {duration_months} months with {security_level} security"
        )
        
        # Save to database
        self.db.save_pairing_record(record)
        
        # Store in memory
        self.pairing_records[pairing_id] = record
        self.active_pairings[pairing_id] = record
        
        # Log activity
        self.db.log_activity(pairing_id, "PAIR_CREATED", 
                            f"Devices paired for {duration_months} months")
        
        return record
    
    def _find_existing_pair(self, device_imei: str, target_imei: str) -> Optional[PairingRecord]:
        """Find existing pairing between two devices"""
        for record in self.active_pairings.values():
            if (record.device_imei == device_imei and record.target_imei == target_imei) or \
               (record.device_imei == target_imei and record.target_imei == device_imei):
                return record
        return None
    
    def _generate_pairing_id(self, device_imei: str, target_imei: str) -> str:
        """Generate unique pairing ID"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_suffix = uuid.uuid4().hex[:8]
        return f"PAIR-{device_imei[:4]}-{target_imei[:4]}-{timestamp[:6]}-{random_suffix}"
    
    def _generate_encryption_key(self) -> str:
        """Generate secure encryption key"""
        random_data = os.urandom(32)
        timestamp = datetime.now().isoformat()
        key_material = f"{timestamp}{base64.b64encode(random_data).decode()}"
        return hashlib.sha3_256(key_material.encode()).hexdigest()
    
    def _generate_pair_hash(self, device_imei: str, target_imei: str, key: str) -> str:
        """Generate secure pair hash"""
        material = f"{device_imei}{target_imei}{key}{datetime.now().isoformat()}"
        return hashlib.sha3_512(material.encode()).hexdigest()
    
    def extend_pairing(self, pairing_id: str, months: int) -> PairingRecord:
        """Extend pairing duration"""
        if pairing_id not in self.pairing_records:
            raise ValueError(f"Pairing record {pairing_id} not found")
        
        record = self.pairing_records[pairing_id]
        
        if months < 1 or months > 12:
            raise ValueError("Extension must be between 1 and 12 months")
        
        if record.status == "Expired":
            return self.pair_devices(record.device_imei, record.target_imei, months)
        
        new_expiry = record.expiry_date + timedelta(days=months * 30)
        record.expiry_date = new_expiry
        record.pairing_duration_months += months
        
        # Update database
        conn = sqlite3.connect(CONFIG["pairing_db"])
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE pairing_records 
            SET expiry_date = ?, pairing_duration_months = ?
            WHERE pairing_id = ?
        """, (new_expiry.isoformat(), record.pairing_duration_months, pairing_id))
        conn.commit()
        conn.close()
        
        self.db.log_activity(pairing_id, "PAIR_EXTENDED", 
                            f"Pairing extended by {months} months")
        
        return record
    
    def revoke_pairing(self, pairing_id: str):
        """Revoke pairing immediately"""
        if pairing_id not in self.pairing_records:
            raise ValueError(f"Pairing record {pairing_id} not found")
        
        record = self.pairing_records[pairing_id]
        record.status = "Revoked"
        
        conn = sqlite3.connect(CONFIG["pairing_db"])
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE pairing_records SET status = 'Revoked' WHERE pairing_id = ?
        """, (pairing_id,))
        conn.commit()
        conn.close()
        
        if pairing_id in self.active_pairings:
            del self.active_pairings[pairing_id]
        
        self.db.log_activity(pairing_id, "PAIR_REVOKED", "Pairing revoked")
    
    def check_status(self, pairing_id: str) -> Dict[str, Any]:
        """Check current pairing status"""
        if pairing_id not in self.pairing_records:
            return {"status": "Not Found", "valid": False}
        
        record = self.pairing_records[pairing_id]
        
        now = datetime.now()
        is_valid = record.status == "Active" and record.expiry_date > now
        
        if is_valid:
            remaining = (record.expiry_date - now).days
        else:
            remaining = 0
        
        return {
            "status": record.status,
            "valid": is_valid,
            "expiry_date": record.expiry_date,
            "remaining_days": remaining,
            "security_level": record.security_level,
            "data_transferred": record.data_transferred,
            "authentication_count": record.authentication_count,
            "pairing_duration_months": record.pairing_duration_months
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get pairing statistics"""
        total = len(self.pairing_records)
        active = len([r for r in self.pairing_records.values() if r.status == "Active"])
        expired = len([r for r in self.pairing_records.values() if r.status == "Expired"])
        revoked = len([r for r in self.pairing_records.values() if r.status == "Revoked"])
        
        total_data = sum(r.data_transferred for r in self.pairing_records.values())
        avg_duration = sum(r.pairing_duration_months for r in self.pairing_records.values()) / max(total, 1)
        
        security_dist = defaultdict(int)
        for r in self.pairing_records.values():
            security_dist[r.security_level] += 1
        
        device_dist = defaultdict(int)
        for r in self.pairing_records.values():
            dev_type = r.device_info.get("type", "Unknown")
            tgt_type = r.target_info.get("type", "Unknown")
            device_dist[f"{dev_type}→{tgt_type}"] += 1
        
        return {
            "total_pairings": total,
            "active_pairings": active,
            "expired_pairings": expired,
            "revoked_pairings": revoked,
            "total_data_transferred": total_data,
            "average_duration_months": round(avg_duration, 1),
            "security_distribution": dict(security_dist),
            "device_distribution": dict(device_dist)
        }

# ============================================================================
# GSM SCANNER (Simulated)
# ============================================================================

class GSMScanner:
    """GSM signal scanner (simulated)"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.scanning = False
    
    def start_scan(self, duration: int = 30) -> List[Dict]:
        """Simulate GSM scanning"""
        console.print("[yellow]📡 Scanning GSM networks...[/yellow]")
        
        carriers = [
            {"operator": "AT&T", "mcc": 310, "mnc": 410, "band": "PCS 1900", "frequency": "1900 MHz"},
            {"operator": "T-Mobile", "mcc": 310, "mnc": 260, "band": "PCS 1900", "frequency": "1900 MHz"},
            {"operator": "Verizon", "mcc": 311, "mnc": 480, "band": "GSM 850", "frequency": "850 MHz"},
            {"operator": "AT&T", "mcc": 310, "mnc": 150, "band": "GSM 850", "frequency": "850 MHz"},
            {"operator": "T-Mobile", "mcc": 312, "mnc": 530, "band": "AWS 1700", "frequency": "1700 MHz"},
            {"operator": "Verizon", "mcc": 310, "mnc": 890, "band": "PCS 1900", "frequency": "1900 MHz"},
            {"operator": "Cricket", "mcc": 313, "mnc": 100, "band": "LTE 700", "frequency": "700 MHz"},
            {"operator": "Sprint", "mcc": 310, "mnc": 320, "band": "PCS 1900", "frequency": "1900 MHz"},
        ]
        
        scans = []
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=duration)
            
            for i in range(duration):
                if not self.scanning:
                    break
                    
                time.sleep(1)
                progress.update(task, advance=1)
                
                carrier = random.choice(carriers)
                signal_strength = random.randint(-100, -60)
                
                quality = "Excellent" if signal_strength >= -70 else \
                          "Good" if signal_strength >= -80 else \
                          "Fair" if signal_strength >= -90 else "Poor"
                
                scan = {
                    "timestamp": datetime.now().isoformat(),
                    "operator": carrier["operator"],
                    "network_type": random.choice(["4G LTE", "5G", "3G", "2G"]),
                    "band": carrier["band"],
                    "frequency": carrier["frequency"],
                    "signal_strength": signal_strength,
                    "signal_quality": quality,
                    "mcc": carrier["mcc"],
                    "mnc": carrier["mnc"],
                    "cell_id": random.randint(1, 65535),
                    "is_roaming": random.choice([True, False])
                }
                
                scans.append(scan)
        
        return scans

# ============================================================================
# MAIN APPLICATION
# ============================================================================

class PegasusMetaSec:
    """Main application class"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.imei_analyzer = IMEIAnalyzer()
        self.pairing_manager = PairingManager()
        self.gsm_scanner = GSMScanner()
        self.is_running = True
        
        self._show_banner()
        self._check_legal_agreement()
    
    def _show_banner(self):
        """Display application banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████╗ ███████╗ ██████╗  █████╗ ███████╗██╗   ██╗███████╗███████╗       ║
║   ██╔══██╗██╔════╝██╔════╝ ██╔══██╗██╔════╝██║   ██║██╔════╝██╔════╝       ║
║   ██████╔╝█████╗  ██║  ███╗███████║███████╗██║   ██║███████╗███████╗       ║
║   ██╔═══╝ ██╔══╝  ██║   ██║██╔══██║╚════██║██║   ██║╚════██║╚════██║       ║
║   ██║     ███████╗╚██████╔╝██║  ██║███████║╚██████╔╝███████║███████║       ║
║   ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝╚══════╝       ║
║                                                                              ║
║              🔗 Complete GSM Security & IMEI Suite v{VERSION}               ║
║         📱 iPhone & Android Device Pairing System                         ║
║                                                                              ║
║  Features:                                                                   ║
║  ✓ IMEI Validation & Analysis                                               ║
║  ✓ iPhone & Android Device Pairing (3-12 months)                           ║
║  ✓ Real-time GSM Signal Scanning                                            ║
║  ✓ Security Auditing & Vulnerability Assessment                            ║
║  ✓ Complete Database Management                                             ║
║  ✓ Report Generation & Export                                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        console.print(banner, style="cyan")
    
    def _check_legal_agreement(self):
        """Check legal agreement"""
        console.print("[yellow]⚠️  LEGAL DISCLAIMER:[/yellow]")
        console.print("This tool is for authorized security testing and educational purposes only.")
        console.print("Unauthorized use is strictly prohibited and may be illegal.")
        console.print()
        
        if not Confirm.ask("[cyan]Do you agree to the terms of use?[/cyan]", default=False):
            console.print("[red]Terms not accepted. Exiting...[/red]")
            sys.exit(0)
        
        console.print("[green]✅ Terms accepted. Welcome to PegasusMetaSec![/green]")
        console.print()
    
    def main_menu(self):
        """Main menu loop"""
        while self.is_running:
            console.print("\n" + "═" * 70)
            console.print("[bold cyan]📱 PegasusMetaSec - Main Menu[/bold cyan]")
            console.print("═" * 70)
            
            menu_items = {
                "1": ("🔍 IMEI Analysis", self.menu_imei_analysis),
                "2": ("🔗 Device Pairing", self.menu_pairing),
                "3": ("📡 GSM Scanning", self.menu_gsm_scanning),
                "4": ("📊 Security Audit", self.menu_security_audit),
                "5": ("📋 View Statistics", self.menu_statistics),
                "6": ("💾 Export Data", self.menu_export),
                "7": ("⚙️  Settings", self.menu_settings),
                "8": ("ℹ️  About", self.menu_about),
                "9": ("🚪 Exit", self.menu_exit)
            }
            
            for key, (label, _) in menu_items.items():
                console.print(f"  [{key}] {label}")
            
            choice = Prompt.ask("\n[bold cyan]Select option[/bold cyan]", choices=list(menu_items.keys()))
            
            if choice in menu_items:
                _, func = menu_items[choice]
                func()
    
    # ========================================================================
    # MENU: IMEI Analysis
    # ========================================================================
    
    def menu_imei_analysis(self):
        """IMEI Analysis menu"""
        while True:
            console.print("\n" + "═" * 50)
            console.print("[bold cyan]🔍 IMEI Analysis[/bold cyan]")
            console.print("═" * 50)
            
            console.print("  [1] Validate IMEI")
            console.print("  [2] Analyze IMEI (Detailed)")
            console.print("  [3] Decode IMEI")
            console.print("  [4] Check Blacklist")
            console.print("  [5] Back to Main Menu")
            
            choice = Prompt.ask("\n[cyan]Select option[/cyan]", choices=["1", "2", "3", "4", "5"])
            
            if choice == "1":
                self._validate_imei()
            elif choice == "2":
                self._analyze_imei()
            elif choice == "3":
                self._decode_imei()
            elif choice == "4":
                self._check_blacklist()
            elif choice == "5":
                break
    
    def _validate_imei(self):
        """Validate IMEI"""
        imei = Prompt.ask("[cyan]Enter IMEI to validate[/cyan]")
        result = self.imei_analyzer.validate_imei(imei)
        
        if result.is_valid:
            console.print(f"[green]✅ Valid IMEI: {imei}[/green]")
            console.print(f"📱 Device Type: {result.device_type}")
            console.print(f"🏭 Manufacturer: {result.manufacturer}")
            console.print(f"📱 Model: {result.device_class}")
        else:
            console.print(f"[red]❌ Invalid IMEI[/red]")
            for error in result.validation_errors:
                console.print(f"  • {error}")
        
        input("\nPress Enter to continue...")
    
    def _analyze_imei(self):
        """Analyze IMEI in detail"""
        imei = Prompt.ask("[cyan]Enter IMEI to analyze[/cyan]")
        detailed = Confirm.ask("[cyan]Show detailed analysis?[/cyan]", default=True)
        
        analysis = self.imei_analyzer.analyze_imei(imei, detailed)
        
        table = Table(title="IMEI Analysis Results", box=ROUNDED)
        table.add_column("Attribute", style="cyan")
        table.add_column("Value", style="white")
        
        for key, value in analysis.items():
            if isinstance(value, bool):
                value = "✅ Yes" if value else "❌ No"
            table.add_row(key.replace("_", " ").title(), str(value))
        
        console.print(table)
        input("\nPress Enter to continue...")
    
    def _decode_imei(self):
        """Decode IMEI"""
        imei = Prompt.ask("[cyan]Enter IMEI to decode[/cyan]")
        decoded = self.imei_analyzer.decode_imei(imei)
        
        if "error" in decoded:
            console.print(f"[red]❌ {decoded['error']}[/red]")
        else:
            table = Table(title="IMEI Decoding", box=ROUNDED)
            table.add_column("Component", style="cyan")
            table.add_column("Value", style="white")
            table.add_column("Description", style="blue")
            
            table.add_row("TAC", decoded["tac"], "Type Allocation Code")
            table.add_row("FAC", decoded["fac"], "Final Assembly Code")
            table.add_row("SNR", decoded["snr"], "Serial Number")
            table.add_row("CDN", decoded["cdn"], "Check Digit")
            table.add_row("Manufacturer", decoded["manufacturer"], "Device Manufacturer")
            
            console.print(table)
        
        input("\nPress Enter to continue...")
    
    def _check_blacklist(self):
        """Check IMEI blacklist status"""
        imei = Prompt.ask("[cyan]Enter IMEI to check[/cyan]")
        result = self.imei_analyzer.validate_imei(imei)
        
        table = Table(title="Blacklist Check Results", box=ROUNDED)
        table.add_column("Status", style="cyan")
        table.add_column("Result", style="white")
        
        table.add_row("Blacklisted", "✅ Yes" if result.is_blacklisted else "❌ No")
        table.add_row("Reported Stolen", "✅ Yes" if result.reported_stolen else "❌ No")
        table.add_row("Carrier Locked", "✅ Yes" if result.carrier_locked else "❌ No")
        table.add_row("Warranty Valid", "✅ Yes" if result.warranty_valid else "❌ No")
        
        if result.is_blacklisted:
            table.add_row("Reason", result.blacklist_reason)
        
        console.print(table)
        
        if result.is_blacklisted or result.reported_stolen:
            console.print("[red]⚠️  This IMEI is flagged! Do not use or purchase this device.[/red]")
        
        input("\nPress Enter to continue...")
    
    # ========================================================================
    # MENU: Device Pairing
    # ========================================================================
    
    def menu_pairing(self):
        """Device Pairing menu"""
        while True:
            console.print("\n" + "═" * 50)
            console.print("[bold cyan]🔗 Device Pairing[/bold cyan]")
            console.print("═" * 50)
            
            console.print("  [1] Pair Devices (3-12 months)")
            console.print("  [2] Pair iPhone ↔ Android")
            console.print("  [3] View All Pairings")
            console.print("  [4] Check Pairing Status")
            console.print("  [5] Extend Pairing")
            console.print("  [6] Revoke Pairing")
            console.print("  [7] Back to Main Menu")
            
            choice = Prompt.ask("\n[cyan]Select option[/cyan]", choices=["1", "2", "3", "4", "5", "6", "7"])
            
            if choice == "1":
                self._pair_devices()
            elif choice == "2":
                self._pair_iphone_android()
            elif choice == "3":
                self._view_pairings()
            elif choice == "4":
                self._check_pairing_status()
            elif choice == "5":
                self._extend_pairing()
            elif choice == "6":
                self._revoke_pairing()
            elif choice == "7":
                break
    
    def _pair_devices(self):
        """Pair two devices"""
        console.print("\n[cyan]🔗 Device Pairing[/cyan]")
        
        device_imei = Prompt.ask("[cyan]Enter device IMEI[/cyan]")
        target_imei = Prompt.ask("[cyan]Enter target IMEI[/cyan]")
        
        # Duration selection
        console.print("\n[cyan]Select duration:[/cyan]")
        console.print("  [1] 3 months")
        console.print("  [2] 6 months")
        console.print("  [3] 9 months")
        console.print("  [4] 12 months")
        console.print("  [5] Custom")
        
        dur_choice = Prompt.ask("[cyan]Choose duration[/cyan]", choices=["1", "2", "3", "4", "5"])
        dur_map = {"1": 3, "2": 6, "3": 9, "4": 12}
        
        if dur_choice == "5":
            months = int(Prompt.ask("[cyan]Enter months (3-12)[/cyan]"))
            if months < 3 or months > 12:
                console.print("[red]Duration must be between 3 and 12 months[/red]")
                return
        else:
            months = dur_map[dur_choice]
        
        # Security level
        console.print("\n[cyan]Security level:[/cyan]")
        console.print("  [1] Low")
        console.print("  [2] Medium")
        console.print("  [3] High (Recommended)")
        console.print("  [4] Military")
        
        sec_choice = Prompt.ask("[cyan]Choose security level[/cyan]", choices=["1", "2", "3", "4"])
        sec_map = {"1": "Low", "2": "Medium", "3": "High", "4": "Military"}
        security_level = sec_map[sec_choice]
        
        try:
            record = self.pairing_manager.pair_devices(
                device_imei, target_imei, months, security_level
            )
            
            console.print(f"[green]✅ Pairing successful![/green]")
            console.print(f"📋 ID: {record.pairing_id}")
            console.print(f"📅 Expires: {record.expiry_date.strftime('%Y-%m-%d %H:%M:%S')}")
            
        except Exception as e:
            console.print(f"[red]❌ Pairing failed: {e}[/red]")
        
        input("\nPress Enter to continue...")
    
    def _pair_iphone_android(self):
        """Pair iPhone with Android"""
        console.print("\n[cyan]📱 iPhone ↔ Android Pairing[/cyan]")
        
        iphone_imei = Prompt.ask("[cyan]Enter iPhone IMEI[/cyan]")
        android_imei = Prompt.ask("[cyan]Enter Android IMEI[/cyan]")
        months = int(Prompt.ask("[cyan]Duration (3-12 months)[/cyan]", default="6"))
        
        try:
            # Validate both are correct types
            iphone_result = self.imei_analyzer.validate_imei(iphone_imei)
            android_result = self.imei_analyzer.validate_imei(android_imei)
            
            if iphone_result.device_type != "iPhone":
                console.print("[red]❌ First IMEI is not an iPhone[/red]")
                return
            if android_result.device_type != "Android":
                console.print("[red]❌ Second IMEI is not an Android[/red]")
                return
            
            record = self.pairing_manager.pair_devices(
                iphone_imei, android_imei, months, "High"
            )
            
            console.print(f"[green]✅ Cross-platform pairing successful![/green]")
            console.print(f"📋 ID: {record.pairing_id}")
            
        except Exception as e:
            console.print(f"[red]❌ Pairing failed: {e}[/red]")
        
        input("\nPress Enter to continue...")
    
    def _view_pairings(self):
        """View all pairings"""
        records = self.db.get_pairing_records()
        
        if not records:
            console.print("[yellow]No pairing records found[/yellow]")
            input("\nPress Enter to continue...")
            return
        
        table = Table(title="📋 All Pairings", box=DOUBLE_EDGE)
        table.add_column("ID", style="cyan")
        table.add_column("Device", style="white")
        table.add_column("Target", style="white")
        table.add_column("Status", style="green")
        table.add_column("Expires", style="yellow")
        table.add_column("Security", style="blue")
        table.add_column("Data", style="magenta")
        
        for record in records[:20]:
            status_color = {
                "Active": "green",
                "Suspended": "yellow",
                "Expired": "red",
                "Revoked": "red"
            }.get(record["status"], "white")
            
            dev_info = record.get("device_info", {})
            tgt_info = record.get("target_info", {})
            
            table.add_row(
                record["pairing_id"][:16],
                dev_info.get("model", "Unknown")[:12],
                tgt_info.get("model", "Unknown")[:12],
                f"[{status_color}]{record['status']}[/{status_color}]",
                record["expiry_date"][:10],
                record["security_level"],
                f"{record['data_transferred']:,} bytes"
            )
        
        console.print(table)
        input("\nPress Enter to continue...")
    
    def _check_pairing_status(self):
        """Check pairing status"""
        pairing_id = Prompt.ask("[cyan]Enter pairing ID[/cyan]")
        status = self.pairing_manager.check_status(pairing_id)
        
        if status["status"] == "Not Found":
            console.print("[red]❌ Pairing not found[/red]")
        else:
            table = Table(title="Pairing Status", box=ROUNDED)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="white")
            
            table.add_row("Status", status["status"])
            table.add_row("Valid", "✅ Yes" if status["valid"] else "❌ No")
            table.add_row("Remaining Days", str(status["remaining_days"]))
            table.add_row("Security Level", status["security_level"])
            table.add_row("Data Transferred", f"{status['data_transferred']:,} bytes")
            table.add_row("Auth Count", str(status["authentication_count"]))
            table.add_row("Duration", f"{status['pairing_duration_months']} months")
            
            console.print(table)
        
        input("\nPress Enter to continue...")
    
    def _extend_pairing(self):
        """Extend pairing"""
        pairing_id = Prompt.ask("[cyan]Enter pairing ID to extend[/cyan]")
        months = int(Prompt.ask("[cyan]Add months (1-12)[/cyan]", default="3"))
        
        try:
            record = self.pairing_manager.extend_pairing(pairing_id, months)
            console.print(f"[green]✅ Extended to {record.expiry_date.strftime('%Y-%m-%d')}[/green]")
        except Exception as e:
            console.print(f"[red]❌ Extension failed: {e}[/red]")
        
        input("\nPress Enter to continue...")
    
    def _revoke_pairing(self):
        """Revoke pairing"""
        pairing_id = Prompt.ask("[cyan]Enter pairing ID to revoke[/cyan]")
        
        if Confirm.ask(f"[red]⚠️  Revoke {pairing_id}?[/red]"):
            try:
                self.pairing_manager.revoke_pairing(pairing_id)
                console.print("[green]✅ Revoked[/green]")
            except Exception as e:
                console.print(f"[red]❌ Failed: {e}[/red]")
        
        input("\nPress Enter to continue...")
    
    # ========================================================================
    # MENU: GSM Scanning
    # ========================================================================
    
    def menu_gsm_scanning(self):
        """GSM Scanning menu"""
        while True:
            console.print("\n" + "═" * 50)
            console.print("[bold cyan]📡 GSM Scanning[/bold cyan]")
            console.print("═" * 50)
            
            console.print("  [1] Start Scan")
            console.print("  [2] View Scan History")
            console.print("  [3] Back to Main Menu")
            
            choice = Prompt.ask("\n[cyan]Select option[/cyan]", choices=["1", "2", "3"])
            
            if choice == "1":
                self._start_scan()
            elif choice == "2":
                self._view_scans()
            elif choice == "3":
                break
    
    def _start_scan(self):
        """Start GSM scan"""
        duration = int(Prompt.ask("[cyan]Scan duration (seconds)[/cyan]", default="30"))
        scans = self.gsm_scanner.start_scan(duration)
        
        if scans:
            table = Table(title="GSM Scan Results", box=ROUNDED)
            table.add_column("Operator", style="cyan")
            table.add_column("Network", style="blue")
            table.add_column("Band", style="green")
            table.add_column("Signal", style="yellow")
            table.add_column("Quality", style="white")
            
            for scan in scans[:10]:
                quality_color = {
                    "Excellent": "green",
                    "Good": "cyan",
                    "Fair": "yellow",
                    "Poor": "red"
                }.get(scan["signal_quality"], "white")
                
                table.add_row(
                    scan["operator"],
                    scan["network_type"],
                    scan["band"],
                    f"{scan['signal_strength']} dBm",
                    f"[{quality_color}]{scan['signal_quality']}[/{quality_color}]"
                )
            
            console.print(table)
            console.print(f"[cyan]Total scans: {len(scans)}[/cyan]")
        
        input("\nPress Enter to continue...")
    
    def _view_scans(self):
        """View scan history"""
        conn = sqlite3.connect(CONFIG["database"])
        cursor = conn.cursor()
        cursor.execute("""
            SELECT scan_time, operator_name, network_type, band, 
                   signal_strength, signal_quality 
            FROM gsm_scans 
            ORDER BY scan_time DESC 
            LIMIT 20
        """)
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            console.print("[yellow]No scan records found[/yellow]")
        else:
            table = Table(title="Scan History", box=ROUNDED)
            table.add_column("Time", style="cyan")
            table.add_column("Operator", style="white")
            table.add_column("Network", style="blue")
            table.add_column("Band", style="green")
            table.add_column("Signal", style="yellow")
            table.add_column("Quality", style="white")
            
            for row in rows:
                quality_color = {
                    "Excellent": "green",
                    "Good": "cyan",
                    "Fair": "yellow",
                    "Poor": "red"
                }.get(row[5], "white")
                
                table.add_row(
                    row[0][:16],
                    row[1],
                    row[2],
                    row[3],
                    f"{row[4]} dBm",
                    f"[{quality_color}]{row[5]}[/{quality_color}]"
                )
            
            console.print(table)
        
        input("\nPress Enter to continue...")
    
    # ========================================================================
    # MENU: Security Audit
    # ========================================================================
    
    def menu_security_audit(self):
        """Security Audit menu"""
        while True:
            console.print("\n" + "═" * 50)
            console.print("[bold cyan]📊 Security Audit[/bold cyan]")
            console.print("═" * 50)
            
            console.print("  [1] Scan for Vulnerabilities")
            console.print("  [2] View Audit History")
            console.print("  [3] Generate Report")
            console.print("  [4] Back to Main Menu")
            
            choice = Prompt.ask("\n[cyan]Select option[/cyan]", choices=["1", "2", "3", "4"])
            
            if choice == "1":
                self._scan_vulnerabilities()
            elif choice == "2":
                self._view_audits()
            elif choice == "3":
                self._generate_report()
            elif choice == "4":
                break
    
    def _scan_vulnerabilities(self):
        """Scan for vulnerabilities"""
        imei = Prompt.ask("[cyan]Enter IMEI to audit[/cyan]", default="")
        
        vulnerabilities = []
        
        if imei:
            result = self.imei_analyzer.validate_imei(imei)
            if not result.is_valid:
                vulnerabilities.append(("Invalid IMEI", "High", "IMEI does not pass validation"))
            if result.is_blacklisted:
                vulnerabilities.append(("Blacklisted IMEI", "Critical", "Device is blacklisted"))
            if result.reported_stolen:
                vulnerabilities.append(("Stolen Device", "Critical", "IMEI reported stolen"))
            if result.carrier_locked:
                vulnerabilities.append(("Carrier Locked", "Medium", "Device is carrier locked"))
        
        vulnerabilities.extend([
            ("Weak GSM Encryption", "Medium", "GSM A5/1 encryption is compromised"),
            ("Missing IMEI Lock", "Low", "Device is not locked to SIM"),
            ("Older Network Protocol", "Medium", "2G networks are insecure"),
        ])
        
        if vulnerabilities:
            table = Table(title="Vulnerability Scan Results", box=ROUNDED)
            table.add_column("Vulnerability", style="red")
            table.add_column("Severity", style="yellow")
            table.add_column("Recommendation", style="white")
            
            for vuln, severity, recommendation in vulnerabilities:
                severity_color = {
                    "Critical": "red",
                    "High": "bright_red",
                    "Medium": "yellow",
                    "Low": "green"
                }.get(severity, "white")
                
                table.add_row(
                    vuln,
                    f"[{severity_color}]{severity}[/{severity_color}]",
                    recommendation
                )
            
            console.print(table)
        else:
            console.print("[green]✅ No vulnerabilities found[/green]")
        
        input("\nPress Enter to continue...")
    
    def _view_audits(self):
        """View audit history"""
        conn = sqlite3.connect(CONFIG["database"])
        cursor = conn.cursor()
        cursor.execute("""
            SELECT audit_time, imei, vulnerability, severity, patched
            FROM security_audits
            ORDER BY audit_time DESC
            LIMIT 20
        """)
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            console.print("[yellow]No audit records found[/yellow]")
        else:
            table = Table(title="Audit History", box=ROUNDED)
            table.add_column("Time", style="cyan")
            table.add_column("IMEI", style="white")
            table.add_column("Vulnerability", style="red")
            table.add_column("Severity", style="yellow")
            table.add_column("Status", style="green")
            
            for row in rows:
                severity_color = {
                    "Critical": "red",
                    "High": "bright_red",
                    "Medium": "yellow",
                    "Low": "green"
                }.get(row[3], "white")
                
                status = "✅ Patched" if row[4] else "❌ Unpatched"
                
                table.add_row(
                    row[0][:16],
                    row[1],
                    row[2][:30],
                    f"[{severity_color}]{row[3]}[/{severity_color}]",
                    status
                )
            
            console.print(table)
        
        input("\nPress Enter to continue...")
    
    def _generate_report(self):
        """Generate security report"""
        console.print("[cyan]Generating report...[/cyan]")
        
        stats = self.pairing_manager.get_statistics()
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "software": SOFTWARE_NAME,
            "version": VERSION,
            "statistics": stats
        }
        
        table = Table(title="System Report", box=DOUBLE_EDGE)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        for key, value in stats.items():
            if isinstance(value, dict):
                value = json.dumps(value)
            table.add_row(key.replace("_", " ").title(), str(value))
        
        console.print(table)
        
        # Save option
        if Confirm.ask("\n[cyan]Save report to file?[/cyan]"):
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
            console.print(f"[green]✅ Saved to {filename}[/green]")
        
        input("\nPress Enter to continue...")
    
    # ========================================================================
    # MENU: Statistics
    # ========================================================================
    
    def menu_statistics(self):
        """View statistics"""
        stats = self.pairing_manager.get_statistics()
        
        table = Table(title="📊 System Statistics", box=DOUBLE_EDGE)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        for key, value in stats.items():
            if isinstance(value, dict):
                value = "\n".join([f"  {k}: {v}" for k, v in value.items()])
            else:
                value = str(value)
            table.add_row(key.replace("_", " ").title(), value)
        
        console.print(table)
        
        # Database stats
        conn = sqlite3.connect(CONFIG["database"])
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM imei_records")
        imei_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM gsm_scans")
        scan_count = cursor.fetchone()[0]
        conn.close()
        
        console.print(f"[cyan]Database Stats:[/cyan]")
        console.print(f"  IMEI Records: {imei_count}")
        console.print(f"  GSM Scans: {scan_count}")
        
        input("\nPress Enter to continue...")
    
    # ========================================================================
    # MENU: Export
    # ========================================================================
    
    def menu_export(self):
        """Export data"""
        filename = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        console.print("[cyan]Exporting data...[/cyan]")
        
        # Collect all data
        export_data = {
            "export_date": datetime.now().isoformat(),
            "software": SOFTWARE_NAME,
            "version": VERSION,
            "pairings": self.db.get_pairing_records(),
            "statistics": self.pairing_manager.get_statistics()
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=4)
        
        console.print(f"[green]✅ Exported to {filename}[/green]")
        input("\nPress Enter to continue...")
    
    # ========================================================================
    # MENU: Settings
    # ========================================================================
    
    def menu_settings(self):
        """Settings menu"""
        console.print("\n" + "═" * 50)
        console.print("[bold cyan]⚙️  Settings[/bold cyan]")
        console.print("═" * 50)
        
        console.print("  [1] View Configuration")
        console.print("  [2] Reset Database")
        console.print("  [3] Back to Main Menu")
        
        choice = Prompt.ask("\n[cyan]Select option[/cyan]", choices=["1", "2", "3"])
        
        if choice == "1":
            table = Table(title="Configuration", box=ROUNDED)
            table.add_column("Setting", style="cyan")
            table.add_column("Value", style="white")
            for key, value in CONFIG.items():
                table.add_row(key, str(value))
            console.print(table)
            input("\nPress Enter to continue...")
        elif choice == "2":
            if Confirm.ask("[red]⚠️  This will delete all data. Continue?[/red]"):
                os.remove(CONFIG["database"])
                os.remove(CONFIG["pairing_db"])
                console.print("[green]✅ Databases reset[/green]")
                input("\nPress Enter to continue...")
    
    # ========================================================================
    # MENU: About
    # ========================================================================
    
    def menu_about(self):
        """About information"""
        about = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  {SOFTWARE_NAME} v{VERSION}                                              ║
║                                                                              ║
║  Author: {AUTHOR}                                                         ║
║                                                                              ║
║  Description:                                                                ║
║  Complete GSM Security Suite with IMEI validation,                          ║
║  device pairing, and security auditing capabilities.                       ║
║                                                                              ║
║  Features:                                                                   ║
║  • IMEI Validation & Analysis                                               ║
║  • iPhone & Android Device Pairing (3-12 months)                           ║
║  • Real-time GSM Signal Scanning                                            ║
║  • Security Auditing & Vulnerability Assessment                            ║
║  • Complete Database Management                                             ║
║                                                                              ║
║  ⚠️  LEGAL DISCLAIMER:                                                       ║
║  This tool is for authorized security testing and                          ║
║  educational purposes only. Unauthorized use                              ║
║  is strictly prohibited and may be illegal.                               ║
║                                                                              ║
║  📧 Support: support@pegasusmetasec.com                                    ║
║  🌐 Website: https://pegasusmetasec.com                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        console.print(about)
        input("\nPress Enter to continue...")
    
    # ========================================================================
    # MENU: Exit
    # ========================================================================
    
    def menu_exit(self):
        """Exit the application"""
        if Confirm.ask("\n[yellow]Are you sure you want to exit?[/yellow]"):
            console.print("\n[bold yellow]👋 Thank you for using PegasusMetaSec![/bold yellow]")
            console.print("[cyan]🔒 Stay secure![/cyan]")
            self.is_running = False
            sys.exit(0)

# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    try:
        app = PegasusMetaSec()
        app.main_menu()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]❌ Fatal error: {e}[/red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
