#!/usr/bin/env python3
"""
Generate demo QR codes for the test batches
"""

import qrcode
import json
from datetime import datetime
import os

def generate_qr_codes():
    """Generate QR codes for test batches"""
    
    # Ensure qr directory exists
    os.makedirs('static/qr_codes', exist_ok=True)
    
    # Load test batches
    with open('batches.json', 'r') as f:
        batches = json.load(f)
    
    base_url = "https://medlock.replit.app"  # Update with actual URL when deployed
    
    for batch in batches:
        batch_id = batch['batch_id']
        
        # Create verification URL with security parameters
        verification_url = f"{base_url}/verify/{batch_id}?qr_data={batch['qr_security_data']['signed_hash']}&location=Demo"
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,  # High error correction
            box_size=10,
            border=4,
        )
        qr.add_data(verification_url)
        qr.make(fit=True)
        
        # Create QR code image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save QR code
        qr_filename = f"static/qr_codes/qr_{batch_id}.png"
        img.save(qr_filename)
        
        print(f"✅ Generated QR code for {batch_id}: {qr_filename}")
        print(f"   URL: {verification_url}")
    
    print(f"\n🎯 Generated {len(batches)} QR codes in static/qr_codes/")

if __name__ == "__main__":
    generate_qr_codes()