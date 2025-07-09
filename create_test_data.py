#!/usr/bin/env python3
"""
Create test data for MedLock demonstration
This script creates realistic test manufacturers and batches to showcase the platform
"""

import json
import uuid
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

def create_test_manufacturers():
    """Create realistic test manufacturer data"""
    manufacturers = [
        {
            "id": str(uuid.uuid4()),
            "company_name": "PharmaCorp Industries",
            "email": "contact@pharmacorp.pharma",
            "license_number": "PHM-2024-001-DELHI",
            "gst_number": "27ABCDE1234F1Z5",
            "password_hash": generate_password_hash("demo123"),
            "approved": True,
            "created_at": (datetime.now() - timedelta(days=30)).isoformat(),
            "approved_at": (datetime.now() - timedelta(days=25)).isoformat(),
            "approved_by": "admin@medlock.com",
            "address": "Sector 8, Industrial Area, New Delhi - 110077",
            "phone": "+91-11-4567-8900",
            "license_document": "pharmacorp_license.pdf"
        },
        {
            "id": str(uuid.uuid4()),
            "company_name": "MediLife Pharmaceuticals",
            "email": "info@medilife.med",
            "license_number": "MED-2024-002-MUMBAI",
            "gst_number": "27FGHIJ5678K2L6",
            "password_hash": generate_password_hash("demo456"),
            "approved": True,
            "created_at": (datetime.now() - timedelta(days=20)).isoformat(),
            "approved_at": (datetime.now() - timedelta(days=15)).isoformat(),
            "approved_by": "admin@medlock.com",
            "address": "Andheri Industrial Estate, Mumbai - 400053",
            "phone": "+91-22-2345-6789",
            "license_document": "medilife_license.pdf"
        },
        {
            "id": str(uuid.uuid4()),
            "company_name": "BioGenesis Labs",
            "email": "regulatory@biogenesis.pharma",
            "license_number": "PHARM-2024-003-BANGALORE",
            "gst_number": "29KLMNO9012P3Q7",
            "password_hash": generate_password_hash("demo789"),
            "approved": False,
            "created_at": datetime.now().isoformat(),
            "address": "Electronic City, Bangalore - 560100",
            "phone": "+91-80-1234-5678",
            "license_document": "biogenesis_license.pdf"
        }
    ]
    return manufacturers

def create_test_batches(manufacturers):
    """Create realistic test batch data"""
    batches = []
    
    # PharmaCorp batches
    pharmacorp = manufacturers[0]
    batches.extend([
        {
            "batch_id": "PC-ASP-240701-001",
            "medicine_name": "Aspirin 75mg",
            "manufacturer_id": pharmacorp["id"],
            "manufacturer_name": pharmacorp["company_name"],
            "manufacturer_license": pharmacorp["license_number"],
            "manufacturing_date": "2024-07-01",
            "expiry_date": "2026-07-01",
            "dosage": "75mg tablets",
            "description": "Low-dose aspirin for cardiovascular protection",
            "qr_filename": "qr_PC-ASP-240701-001.png",
            "qr_security_data": {
                "signed_hash": "a1b2c3d4e5f6g7h8i9j0",
                "timestamp": datetime.now().isoformat()
            },
            "blockchain_hash": "0x1a2b3c4d5e6f7890abcdef1234567890fedcba",
            "blockchain_tx": "0xabcdef1234567890fedcba0987654321",
            "upload_date": (datetime.now() - timedelta(days=10)).isoformat(),
            "scan_count": 15,
            "last_scanned": (datetime.now() - timedelta(hours=2)).isoformat(),
            "security_level": "ultra_high",
            "ai_verified": True
        },
        {
            "batch_id": "PC-PAR-240615-002",
            "medicine_name": "Paracetamol 500mg",
            "manufacturer_id": pharmacorp["id"],
            "manufacturer_name": pharmacorp["company_name"],
            "manufacturer_license": pharmacorp["license_number"],
            "manufacturing_date": "2024-06-15",
            "expiry_date": "2026-06-15",
            "dosage": "500mg tablets",
            "description": "Pain relief and fever reducer",
            "qr_filename": "qr_PC-PAR-240615-002.png",
            "qr_security_data": {
                "signed_hash": "b2c3d4e5f6g7h8i9j0k1",
                "timestamp": datetime.now().isoformat()
            },
            "blockchain_hash": "0x2b3c4d5e6f7890abcdef1234567890fedcbb",
            "blockchain_tx": "0xbcdef1234567890fedcba0987654322",
            "upload_date": (datetime.now() - timedelta(days=5)).isoformat(),
            "scan_count": 8,
            "last_scanned": (datetime.now() - timedelta(hours=6)).isoformat(),
            "security_level": "ultra_high",
            "ai_verified": True
        }
    ])
    
    # MediLife batches
    medilife = manufacturers[1]
    batches.extend([
        {
            "batch_id": "ML-AMX-240620-001",
            "medicine_name": "Amoxicillin 250mg",
            "manufacturer_id": medilife["id"],
            "manufacturer_name": medilife["company_name"],
            "manufacturer_license": medilife["license_number"],
            "manufacturing_date": "2024-06-20",
            "expiry_date": "2025-12-20",
            "dosage": "250mg capsules",
            "description": "Broad-spectrum antibiotic",
            "qr_filename": "qr_ML-AMX-240620-001.png",
            "qr_security_data": {
                "signed_hash": "c3d4e5f6g7h8i9j0k1l2",
                "timestamp": datetime.now().isoformat()
            },
            "blockchain_hash": "0x3c4d5e6f7890abcdef1234567890fedcbc",
            "blockchain_tx": "0xcdef1234567890fedcba0987654323",
            "upload_date": (datetime.now() - timedelta(days=3)).isoformat(),
            "scan_count": 25,
            "last_scanned": (datetime.now() - timedelta(minutes=30)).isoformat(),
            "security_level": "ultra_high",
            "ai_verified": True
        }
    ])
    
    return batches

def create_test_scan_logs():
    """Create realistic scan log data"""
    scan_logs = []
    
    # Create various scan patterns
    base_time = datetime.now() - timedelta(days=7)
    
    for i in range(50):
        scan_time = base_time + timedelta(hours=i*2, minutes=i*5)
        scan_logs.append({
            "scan_id": str(uuid.uuid4()),
            "batch_id": ["PC-ASP-240701-001", "PC-PAR-240615-002", "ML-AMX-240620-001"][i % 3],
            "timestamp": scan_time.isoformat(),
            "location": ["Delhi", "Mumbai", "Bangalore", "Chennai", "Kolkata"][i % 5],
            "ip_address": f"192.168.{i%10}.{(i*7)%256}",
            "user_agent": "Mozilla/5.0 (Mobile; Android)" if i % 3 == 0 else "Mozilla/5.0 (iPhone; iOS)",
            "verification_result": "verified" if i % 10 != 9 else "suspicious"
        })
    
    return scan_logs

def main():
    """Create and save all test data"""
    print("🔬 Creating comprehensive test data for MedLock...")
    
    # Create test data
    manufacturers = create_test_manufacturers()
    batches = create_test_batches(manufacturers)
    scan_logs = create_test_scan_logs()
    
    # Save to files
    with open('manufacturers.json', 'w') as f:
        json.dump(manufacturers, f, indent=2)
    print(f"✅ Created {len(manufacturers)} test manufacturers")
    
    with open('batches.json', 'w') as f:
        json.dump(batches, f, indent=2)
    print(f"✅ Created {len(batches)} test batches")
    
    with open('scan_logs.json', 'w') as f:
        json.dump(scan_logs, f, indent=2)
    print(f"✅ Created {len(scan_logs)} scan log entries")
    
    print("\n🎯 Test Login Credentials:")
    print("Manufacturer 1: contact@pharmacorp.pharma / demo123")
    print("Manufacturer 2: info@medilife.med / demo456")
    print("Admin: admin@medlock.com / admin123")
    
    print("\n🔍 Test Batch IDs for verification:")
    for batch in batches:
        print(f"- {batch['batch_id']} ({batch['medicine_name']})")
    
    print("\n🚀 Test data created successfully!")

if __name__ == "__main__":
    main()