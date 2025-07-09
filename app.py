import os
import json
import uuid
import qrcode
import hashlib
import hmac
import secrets
import re
import zipfile
import tempfile
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify, send_file, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import logging
import csv
import io

# Import AI and Blockchain modules  
from ai_fraud_detector import AIFraudDetector
from blockchain_integration import BlockchainVerifier

# Set up logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "your-secret-key-for-demo")

# Initialize AI and Blockchain systems
ai_detector = AIFraudDetector()
blockchain_verifier = BlockchainVerifier()

# Configuration
UPLOAD_FOLDER = 'static/uploads'
QR_FOLDER = 'qr/'
DATA_FOLDER = 'data/'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Security configuration
SECRET_QR_KEY = os.environ.get("QR_SECRET_KEY", "medlock-qr-secret-key-2025")
REPLIT_URL = os.environ.get("REPL_SLUG", "medlock").replace(" ", "-").lower() + "." + os.environ.get("REPL_OWNER", "username").replace(" ", "-").lower() + ".repl.co"

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QR_FOLDER, exist_ok=True)
os.makedirs(DATA_FOLDER, exist_ok=True)
os.makedirs('static/', exist_ok=True)
os.makedirs('templates/', exist_ok=True)

# Admin credentials (hardcoded for demo)
ADMIN_EMAIL = "admin@medlock.com"
ADMIN_PASSWORD = "admin123"

# Semi-automated approval patterns
TRUSTED_EMAIL_DOMAINS = [".pharma", ".med", "pharmaplus.in", "medco.com"]
TRUSTED_LICENSE_PREFIXES = ["PHM-", "MED-", "PHARM-"]

def load_flags():
    """Load flagged scans from file"""
    try:
        with open(f'{DATA_FOLDER}flags.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_flags(flags):
    """Save flagged scans to file"""
    with open(f'{DATA_FOLDER}flags.json', 'w') as f:
        json.dump(flags, f, indent=2)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_manufacturers():
    try:
        with open(f'{DATA_FOLDER}manufacturers.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_manufacturers(manufacturers):
    with open(f'{DATA_FOLDER}manufacturers.json', 'w') as f:
        json.dump(manufacturers, f, indent=2)

def load_batches():
    try:
        with open(f'{DATA_FOLDER}batches.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_batches(batches):
    with open(f'{DATA_FOLDER}batches.json', 'w') as f:
        json.dump(batches, f, indent=2)

def load_scan_logs():
    try:
        with open(f'{DATA_FOLDER}scan_logs.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_scan_logs(scan_logs):
    with open(f'{DATA_FOLDER}scan_logs.json', 'w') as f:
        json.dump(scan_logs, f, indent=2)

def should_auto_approve_manufacturer(email, license_number):
    """
    Semi-automated manufacturer approval logic
    Auto-approve if:
    - Email domain ends with .pharma or .med
    - License format starts with PHM-, MED-, or PHARM-
    """
    email_domain_approved = any(domain in email.lower() for domain in TRUSTED_EMAIL_DOMAINS)
    license_format_approved = any(license_number.upper().startswith(prefix) for prefix in TRUSTED_LICENSE_PREFIXES)
    
    return email_domain_approved and license_format_approved

def log_scan_with_flagging(batch_id, location, ip_address="192.168.1.1"):
    """
    Log QR scan and check for suspicious patterns
    Flag if same QR scanned in multiple cities within short time
    """
    scan_logs = load_scan_logs()
    
    # Create new scan entry
    new_scan = {
        'batch_id': batch_id,
        'timestamp': datetime.now().isoformat(),
        'location': location,
        'ip_address': ip_address,
        'scan_id': str(uuid.uuid4())
    }
    
    scan_logs.append(new_scan)
    save_scan_logs(scan_logs)
    
    # Check for suspicious patterns
    batch_scans = [log for log in scan_logs if log['batch_id'] == batch_id]
    
    # Flag if scanned in multiple different locations within 24 hours
    recent_scans = []
    current_time = datetime.now()
    
    for scan in batch_scans:
        try:
            scan_time = datetime.fromisoformat(scan['timestamp'])
            if (current_time - scan_time).total_seconds() < 86400:  # 24 hours
                recent_scans.append(scan)
        except:
            continue
    
    # Get unique locations from recent scans
    recent_locations = set([scan.get('location', '') for scan in recent_scans if scan.get('location')])
    
    # Flag if more than 3 different locations in 24 hours
    if len(recent_locations) > 3:
        flags = load_flags()
        flag_entry = {
            'batch_id': batch_id,
            'flag_reason': f"Scanned in {len(recent_locations)} different locations within 24 hours",
            'locations': list(recent_locations),
            'flagged_at': datetime.now().isoformat(),
            'scan_count': len(recent_scans),
            'status': 'flagged'
        }
        flags.append(flag_entry)
        save_flags(flags)
        
        logging.warning(f"🚨 FLAGGED: Batch {batch_id} scanned in multiple locations: {recent_locations}")
        
        return {'flagged': True, 'reason': flag_entry['flag_reason']}
    
    return {'flagged': False}

def load_email_verifications():
    try:
        with open('email_verifications.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_email_verifications(verifications):
    with open('email_verifications.json', 'w') as f:
        json.dump(verifications, f, indent=2)

def generate_secure_token(batch_id, manufacturer_license):
    """Generate secure token for QR code verification"""
    data = f"{batch_id}:{manufacturer_license}:{datetime.now().strftime('%Y%m%d')}"
    return hmac.new(SECRET_QR_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]

def verify_secure_token(batch_id, manufacturer_license, token):
    """Verify the security token in QR code"""
    # Check tokens for current day and previous day (in case of timezone differences)
    for days_back in [0, 1]:
        check_date = (datetime.now() - timedelta(days=days_back)).strftime('%Y%m%d')
        data = f"{batch_id}:{manufacturer_license}:{check_date}"
        expected_token = hmac.new(SECRET_QR_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
        if hmac.compare_digest(token, expected_token):
            return True
    return False

def is_trusted_manufacturer(email, gst_number):
    """Check if manufacturer should be auto-approved"""
    # Check against trusted email list
    if email in TRUSTED_MANUFACTURERS:
        return TRUSTED_MANUFACTURERS[email]["gst"] == gst_number
    
    # Check against trusted domains
    domain = email.split('@')[1] if '@' in email else ''
    return domain in TRUSTED_EMAIL_DOMAINS

# Email verification removed - direct registration process

def get_client_ip():
    """Get client IP address"""
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ.get('REMOTE_ADDR', 'unknown')
    else:
        return request.environ.get('HTTP_X_FORWARDED_FOR').split(',')[0].strip()

def log_scan_activity(batch_id, ip_address, user_agent=''):
    """Log scan activity for monitoring"""
    scan_logs = load_scan_logs()
    
    scan_entry = {
        'batch_id': batch_id,
        'ip_address': ip_address,
        'user_agent': user_agent,
        'timestamp': datetime.now().isoformat(),
        'scan_id': str(uuid.uuid4())
    }
    
    scan_logs.append(scan_entry)
    save_scan_logs(scan_logs)
    
    return scan_entry

def analyze_suspicious_activity(batch_id):
    """Analyze scan patterns for suspicious behavior"""
    scan_logs = load_scan_logs()
    batch_scans = [log for log in scan_logs if log['batch_id'] == batch_id]
    
    suspicious_flags = []
    
    if not batch_scans:
        return suspicious_flags
    
    # Check for excessive scans from same IP
    ip_counts = defaultdict(int)
    for scan in batch_scans:
        ip_counts[scan['ip_address']] += 1
    
    for ip, count in ip_counts.items():
        if count > 10:  # More than 10 scans from same IP
            suspicious_flags.append(f"Excessive scans ({count}) from IP: {ip}")
    
    # Check for scans in short time window
    recent_scans = []
    now = datetime.now()
    for scan in batch_scans:
        scan_time = datetime.fromisoformat(scan['timestamp'])
        if (now - scan_time).total_seconds() < 3600:  # Last hour
            recent_scans.append(scan)
    
    if len(recent_scans) > 20:
        suspicious_flags.append(f"High frequency scanning: {len(recent_scans)} scans in last hour")
    
    # Check for diverse geographic patterns (simulated)
    unique_ips = len(set(scan['ip_address'] for scan in recent_scans))
    if unique_ips > 15 and len(recent_scans) > 20:
        suspicious_flags.append("Potential bot scanning: diverse IP addresses in short time")
    
    return suspicious_flags

def check_batch_expiry(expiry_date_str):
    """Check if batch has expired"""
    try:
        expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d')
        return datetime.now() > expiry_date
    except:
        return False

def validate_manufacturer_license(license_number):
    """Validate manufacturer license format and status"""
    # Basic validation - in real implementation, check against regulatory database
    if not license_number or len(license_number) < 10:
        return False, "Invalid license number format"
    
    # Simulate license validation
    if license_number.startswith('FAKE') or license_number.startswith('TEST'):
        return False, "Invalid or test license number"
    
    return True, "License valid"

def generate_secure_qr_code(batch_id, batch_data, manufacturer_license):
    """
    Generate ultra-secure QR code with blockchain integration and AI verification
    Features:
    - Signed hash instead of raw batch_id
    - Blockchain storage for tamper detection
    - AI-powered security analysis
    """
    try:
        # Generate blockchain-secured QR data
        qr_result = blockchain_verifier.generate_secure_qr_data(batch_id, batch_data, manufacturer_license)
        if not qr_result:
            logging.error("Failed to generate secure QR data")
            return None, None
        
        qr_data_string = qr_result['qr_data']
        
        # Create QR code with enhanced error correction
        qr = qrcode.QRCode(
            version=3,  # Higher version for more data
            error_correction=qrcode.constants.ERROR_CORRECT_H,  # Highest error correction
            box_size=12,
            border=6,
        )
        
        # Use proper Replit URL that works on phones
        replit_slug = os.environ.get("REPL_SLUG", "workspace") 
        replit_owner = os.environ.get("REPL_OWNER", "guptapalak09200")
        base_url = f"https://{replit_slug}.{replit_owner}.repl.co"
        
        # Encode verification URL with signed data
        verify_url = f"{base_url}/verify/{batch_id}?qr_data={qr_data_string}"
        
        qr.add_data(verify_url)
        qr.make(fit=True)
        
        # Generate QR code image with enhanced security features
        img = qr.make_image(fill_color="#1e3a8a", back_color="white")
        
        # Create unique filename with hash prefix
        hash_prefix = qr_result['full_hash'][:8]
        qr_filename = f"SECURE_{batch_id}_{hash_prefix}.png"
        qr_path = os.path.join(QR_FOLDER, qr_filename)
        img.save(qr_path)
        
        logging.info(f"✅ Generated secure QR code for batch {batch_id}")
        
        return qr_filename, qr_result
        
    except Exception as e:
        logging.error(f"QR generation error: {e}")
        return None, None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/demo')
def demo():
    """Demo test bench page"""
    return render_template('demo.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        company_name = request.form['company_name']
        email = request.form['email']
        gst_number = request.form['gst_number']
        license_number = request.form['license_number']
        password = request.form['password']
        
        # Check if file was uploaded
        if 'license_file' not in request.files:
            flash('License file is required', 'error')
            return redirect(request.url)
        
        file = request.files['license_file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Add timestamp to filename to avoid conflicts
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            
            # Load existing manufacturers
            manufacturers = load_manufacturers()
            
            # Check if email already exists
            for manufacturer in manufacturers:
                if manufacturer['email'] == email:
                    flash('Email already registered', 'error')
                    return redirect(request.url)
            
            # Semi-automated approval check
            auto_approved = should_auto_approve_manufacturer(email, license_number)
            approval_status = 'approved' if auto_approved else 'pending'
            
            # Create new manufacturer
            new_manufacturer = {
                'id': str(uuid.uuid4()),
                'company_name': company_name,
                'email': email,
                'gst_number': gst_number,
                'license_number': license_number,
                'password_hash': generate_password_hash(password),
                'license_file': filename,
                'approved': auto_approved,
                'approval_status': approval_status,
                'created_at': datetime.now().isoformat(),
                'approved_at': datetime.now().isoformat() if auto_approved else None
            }
            
            manufacturers.append(new_manufacturer)
            save_manufacturers(manufacturers)
            
            if auto_approved:
                flash('✅ Registration successful! Auto-approved due to trusted domain/license format.', 'success')
                logging.info(f"Auto-approved manufacturer: {email} with license {license_number}")
            else:
                flash('📋 Registration successful! Pending admin approval.', 'info')
            
            return redirect(url_for('login'))
        else:
            flash('Invalid file type. Please upload PDF, PNG, JPG, JPEG, or GIF files.', 'error')
    
    return render_template('register.html')

# Email verification function removed - direct registration now

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        manufacturers = load_manufacturers()
        
        for manufacturer in manufacturers:
            if manufacturer['email'] == email and check_password_hash(manufacturer['password_hash'], password):
                if not manufacturer['approved']:
                    flash('Your account is under review.', 'warning')
                    return redirect(request.url)
                
                session['manufacturer_id'] = manufacturer['id']
                session['manufacturer_email'] = manufacturer['email']
                session['company_name'] = manufacturer['company_name']
                return redirect(url_for('manufacturer_dashboard'))
        
        flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    manufacturers = load_manufacturers()
    batches = load_batches()
    scan_logs = load_scan_logs()
    
    # Categorize manufacturers
    pending_manufacturers = [m for m in manufacturers if not m.get('approved', False)]
    approved_manufacturers = [m for m in manufacturers if m.get('approved', False)]
    auto_approved = [m for m in approved_manufacturers if m.get('approval_status') == 'approved']
    
    # Calculate statistics
    total_batches = len(batches)
    total_scans = len(scan_logs)
    
    # Find suspicious batches
    suspicious_batches = []
    for batch in batches:
        flags = analyze_suspicious_activity(batch['batch_id'])
        if flags:
            suspicious_batches.append({
                'batch': batch,
                'flags': flags
            })
    
    # Recent activity (last 24 hours)
    recent_scans = []
    cutoff_time = datetime.now() - timedelta(hours=24)
    for scan in scan_logs:
        scan_time = datetime.fromisoformat(scan['timestamp'])
        if scan_time > cutoff_time:
            recent_scans.append(scan)
    
    # Top scanned batches
    batch_scan_counts = defaultdict(int)
    for scan in scan_logs:
        batch_scan_counts[scan['batch_id']] += 1
    
    top_batches = []
    for batch in batches:
        scan_count = batch_scan_counts[batch['batch_id']]
        if scan_count > 0:
            top_batches.append({
                'batch': batch,
                'scan_count': scan_count
            })
    top_batches.sort(key=lambda x: x['scan_count'], reverse=True)
    
    dashboard_data = {
        'manufacturers': manufacturers,
        'pending_manufacturers': pending_manufacturers,
        'approved_manufacturers': approved_manufacturers,
        'auto_approved_manufacturers': auto_approved,
        'total_batches': total_batches,
        'total_scans': total_scans,
        'suspicious_batches': suspicious_batches,
        'recent_scans': recent_scans[:20],  # Last 20 scans
        'top_batches': top_batches[:10],  # Top 10 most scanned
        'stats': {
            'pending_count': len(pending_manufacturers),
            'approved_count': len(approved_manufacturers),
            'auto_approved_count': len(auto_approved),
            'suspicious_count': len(suspicious_batches),
            'recent_scans_count': len(recent_scans)
        }
    }
    
    return render_template('admin_dashboard.html', **dashboard_data)

@app.route('/admin/approve/<manufacturer_id>')
def approve_manufacturer(manufacturer_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    manufacturers = load_manufacturers()
    for manufacturer in manufacturers:
        if manufacturer['id'] == manufacturer_id:
            manufacturer['approved'] = True
            manufacturer['approval_status'] = 'manually_approved'
            manufacturer['approved_by'] = 'admin'
            manufacturer['approved_at'] = datetime.now().isoformat()
            break
    
    save_manufacturers(manufacturers)
    flash('Manufacturer approved successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject/<manufacturer_id>')
def reject_manufacturer(manufacturer_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    manufacturers = load_manufacturers()
    manufacturers = [m for m in manufacturers if m['id'] != manufacturer_id]
    
    save_manufacturers(manufacturers)
    flash('Manufacturer rejected and removed', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/revoke/<manufacturer_id>')
def revoke_manufacturer(manufacturer_id):
    """Revoke manufacturer approval"""
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    manufacturers = load_manufacturers()
    for manufacturer in manufacturers:
        if manufacturer['id'] == manufacturer_id:
            manufacturer['approved'] = False
            manufacturer['approval_status'] = 'revoked'
            manufacturer['revoked_by'] = 'admin'
            manufacturer['revoked_at'] = datetime.now().isoformat()
            break
    
    save_manufacturers(manufacturers)
    flash('Manufacturer approval revoked', 'warning')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/scan_logs')
def admin_scan_logs():
    """View detailed scan logs"""
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    scan_logs = load_scan_logs()
    batches = load_batches()
    
    # Create batch lookup for display
    batch_lookup = {batch['batch_id']: batch for batch in batches}
    
    # Add batch info to scan logs
    enhanced_logs = []
    for log in scan_logs[-100:]:  # Last 100 scans
        enhanced_log = log.copy()
        if log['batch_id'] in batch_lookup:
            enhanced_log['batch_info'] = batch_lookup[log['batch_id']]
        else:
            enhanced_log['batch_info'] = {'medicine_name': 'Unknown', 'company_name': 'Unknown'}
        enhanced_logs.append(enhanced_log)
    
    enhanced_logs.reverse()  # Show most recent first
    
    return render_template('admin_scan_logs.html', scan_logs=enhanced_logs)

@app.route('/admin/batch_details/<batch_id>')
def admin_batch_details(batch_id):
    """View detailed batch information and scan history"""
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    batches = load_batches()
    scan_logs = load_scan_logs()
    
    batch = None
    for b in batches:
        if b['batch_id'] == batch_id:
            batch = b
            break
    
    if not batch:
        flash('Batch not found', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Get scan history for this batch
    batch_scans = [log for log in scan_logs if log['batch_id'] == batch_id]
    batch_scans.reverse()  # Most recent first
    
    # Analyze suspicious activity
    suspicious_flags = analyze_suspicious_activity(batch_id)
    
    # Check expiry status
    expired = check_batch_expiry(batch['expiry_date'])
    
    return render_template('admin_batch_details.html', 
                         batch=batch, 
                         scan_logs=batch_scans,
                         suspicious_flags=suspicious_flags,
                         expired=expired)

@app.route('/admin/manufacturer_details/<manufacturer_id>')
def admin_manufacturer_details(manufacturer_id):
    """View detailed manufacturer information and their batches"""
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    manufacturers = load_manufacturers()
    batches = load_batches()
    
    manufacturer = None
    for m in manufacturers:
        if m['id'] == manufacturer_id:
            manufacturer = m
            break
    
    if not manufacturer:
        flash('Manufacturer not found', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Get manufacturer's batches
    manufacturer_batches = [b for b in batches if b['manufacturer_id'] == manufacturer_id]
    
    # Calculate statistics
    total_batches = len(manufacturer_batches)
    total_scans = sum(batch.get('scan_count', 0) for batch in manufacturer_batches)
    
    return render_template('admin_manufacturer_details.html',
                         manufacturer=manufacturer,
                         batches=manufacturer_batches,
                         total_batches=total_batches,
                         total_scans=total_scans)

@app.route('/admin/view_document/<filename>')
def view_document(filename):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/manufacturer_dashboard')
def manufacturer_dashboard():
    if 'manufacturer_id' not in session:
        return redirect(url_for('login'))
    
    batches = load_batches()
    manufacturer_batches = [b for b in batches if b['manufacturer_id'] == session['manufacturer_id']]
    
    return render_template('manufacturer_dashboard.html', batches=manufacturer_batches)

@app.route('/batch_upload', methods=['GET', 'POST'])
def batch_upload():
    if 'manufacturer_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Get form data
        medicine_name = request.form['medicine_name']
        batch_id = request.form['batch_id']
        manufacturing_date = request.form['manufacturing_date']
        expiry_date = request.form['expiry_date']
        dosage = request.form['dosage']
        description = request.form.get('description', '')
        
        # Load batches to check for duplicates
        batches = load_batches()
        
        # Check if batch_id already exists
        for batch in batches:
            if batch['batch_id'] == batch_id:
                flash('Batch ID already exists. Please use a unique Batch ID.', 'error')
                return redirect(request.url)
        
        # Get manufacturer info
        manufacturers = load_manufacturers()
        manufacturer = None
        for m in manufacturers:
            if m['id'] == session['manufacturer_id']:
                manufacturer = m
                break
        
        if not manufacturer:
            flash('Manufacturer not found', 'error')
            return redirect(url_for('logout'))
        
        # Create batch data for blockchain storage
        batch_data = {
            'batch_id': batch_id,
            'medicine_name': medicine_name,
            'manufacturer_name': manufacturer['company_name'],
            'manufacturer_license': manufacturer['license_number'],
            'manufacturing_date': manufacturing_date,
            'expiry_date': expiry_date,
            'dosage': dosage,
            'description': description
        }
        
        # Generate secure QR code with blockchain integration
        qr_filename, qr_result = generate_secure_qr_code(batch_id, batch_data, manufacturer['license_number'])
        if not qr_filename:
            flash('Failed to generate secure QR code. Please try again.', 'error')
            return redirect(request.url)
        
        # Store batch hash on blockchain
        blockchain_result = blockchain_verifier.store_batch_on_blockchain(
            batch_id, batch_data, manufacturer['license_number']
        )
        
        # Create batch entry with blockchain integration
        batch_entry = {
            'batch_id': batch_id,
            'medicine_name': medicine_name,
            'manufacturer_id': manufacturer['id'],
            'manufacturer_name': manufacturer['company_name'],
            'manufacturer_license': manufacturer['license_number'],
            'manufacturing_date': manufacturing_date,
            'expiry_date': expiry_date,
            'dosage': dosage,
            'description': description,
            'qr_filename': qr_filename,
            'qr_security_data': qr_result,
            'blockchain_hash': blockchain_result['transaction']['data_hash'] if blockchain_result else None,
            'blockchain_tx': blockchain_result['transaction']['transaction_hash'] if blockchain_result else None,
            'upload_date': datetime.now().isoformat(),
            'scan_count': 0,
            'last_scanned': None,
            'security_level': 'ultra_high',
            'ai_verified': True
        }
        
        batches.append(batch_entry)
        save_batches(batches)
        
        if blockchain_result:
            flash('✅ Batch uploaded with blockchain security! Ultra-secure QR code generated.', 'success')
            logging.info(f"Blockchain integration successful for batch {batch_id}")
        else:
            flash('⚠️ Batch uploaded with basic security (blockchain unavailable).', 'warning')
        
        return redirect(url_for('manufacturer_dashboard'))
    
    return render_template('batch_upload.html')

@app.route('/verify/<batch_id>')
def verify_batch(batch_id):
    """
    Advanced AI-powered verification with blockchain integrity check
    """
    # Get QR data and location for analysis
    qr_data = request.args.get('qr_data', '')
    location = request.args.get('location', 'Unknown')
    client_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')
    
    # Log scan with flagging system
    flagging_result = log_scan_with_flagging(batch_id, location, client_ip)
    
    # Find batch in database
    batches = load_batches()
    batch_found = None
    
    for batch in batches:
        if batch['batch_id'] == batch_id:
            batch_found = batch
            break
    
    if not batch_found:
        return render_template('verify.html', 
                             batch_id=batch_id, 
                             genuine=False,
                             verification_status='not_found',
                             error_message="Batch not found in our records")
    
    # Prepare batch data for AI analysis
    batch_data = {
        'batch_id': batch_found['batch_id'],
        'medicine_name': batch_found['medicine_name'],
        'manufacturer_name': batch_found.get('manufacturer_name', ''),
        'manufacturer_license': batch_found.get('manufacturer_license', ''),
        'manufacturing_date': batch_found.get('manufacturing_date', ''),
        'expiry_date': batch_found.get('expiry_date', ''),
        'dosage': batch_found.get('dosage', ''),
        'description': batch_found.get('description', ''),
        'created_at': batch_found.get('created_at', 'N/A')
    }
    
    # Blockchain verification
    blockchain_verified = False
    blockchain_result = None
    if batch_found.get('blockchain_hash'):
        blockchain_result = blockchain_verifier.verify_batch_from_blockchain(batch_id, batch_data)
        blockchain_verified = blockchain_result.get('verified', False)
    
    # AI-powered fraud detection
    scan_logs = load_scan_logs()
    ai_analysis = ai_detector.generate_fraud_report(batch_data, scan_logs, batch_found.get('blockchain_hash'))
    
    # QR signature verification if available
    qr_signature_valid = True
    if qr_data:
        qr_verification = blockchain_verifier.verify_qr_signature(qr_data, batch_data)
        qr_signature_valid = qr_verification.get('valid', False)
    
    # Check expiry
    expired = check_batch_expiry(batch_found.get('expiry_date', ''))
    
    # Update scan count
    batch_found['scan_count'] = batch_found.get('scan_count', 0) + 1
    batch_found['last_scanned'] = datetime.now().isoformat()
    save_batches(batches)
    
    # Determine overall verification status
    verification_status = 'verified'
    risk_level = 'low'
    
    if not blockchain_verified and batch_found.get('blockchain_hash'):
        verification_status = 'tampered'
        risk_level = 'critical'
    elif ai_analysis['overall_risk_score'] > 0.7:
        verification_status = 'suspicious'
        risk_level = 'high'
    elif ai_analysis['overall_risk_score'] > 0.3:
        verification_status = 'warning'
        risk_level = 'medium'
    elif expired:
        verification_status = 'expired'
        risk_level = 'medium'
    elif not qr_signature_valid:
        verification_status = 'invalid_qr'
        risk_level = 'high'
    
    # Prepare comprehensive verification result
    verification_result = {
        'batch_id': batch_id,
        'batch': batch_found,
        'genuine': verification_status in ['verified', 'warning'],
        'verification_status': verification_status,
        'risk_level': risk_level,
        'ai_analysis': ai_analysis,
        'blockchain_verified': blockchain_verified,
        'blockchain_result': blockchain_result,
        'qr_signature_valid': qr_signature_valid,
        'expired': expired,
        'flagged': flagging_result.get('flagged', False),
        'flagging_reason': flagging_result.get('reason', ''),
        'scan_count': batch_found['scan_count'],
        'verification_time': datetime.now().isoformat(),
        'security_features': {
            'blockchain_protection': bool(batch_found.get('blockchain_hash')),
            'ai_verification': ai_analysis.get('ai_enabled', False),
            'qr_signature': bool(qr_data),
            'scan_monitoring': True
        }
    }
    
    # Add security warnings
    warnings = []
    if expired:
        warnings.append("🚨 EXPIRED: This medicine has passed its expiry date")
    if not blockchain_verified and batch_found.get('blockchain_hash'):
        warnings.append("🚨 BLOCKCHAIN TAMPERING: Data integrity compromised")
    if ai_analysis['batch_analysis']['is_suspicious']:
        warnings.append("🤖 AI ALERT: Potential counterfeit detected")
    if ai_analysis['pattern_analysis']['suspicious']:
        warnings.append("📊 SCANNING ALERT: Suspicious distribution pattern")
    if flagging_result.get('flagged'):
        warnings.append(f"🏴 FLAGGED: {flagging_result['reason']}")
    if not qr_signature_valid and qr_data:
        warnings.append("🔐 QR SIGNATURE: Invalid security signature")
    
    verification_result['warnings'] = warnings
    
    return render_template('verify.html', **verification_result)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin', None)
    flash('Admin logged out successfully', 'success')
    return redirect(url_for('index'))

# Export routes for admin dashboard
@app.route('/admin/export/scan_logs')
def export_scan_logs():
    """Export scan logs as CSV"""
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    scan_logs = load_scan_logs()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Timestamp', 'Batch ID', 'Location', 'IP Address', 'User Agent', 'Scan ID'])
    
    # Write data
    for log in scan_logs:
        writer.writerow([
            log.get('timestamp', ''),
            log.get('batch_id', ''),
            log.get('location', ''),
            log.get('ip_address', ''),
            log.get('user_agent', ''),
            log.get('scan_id', '')
        ])
    
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=medlock_scan_logs.csv'}
    )

@app.route('/admin/export/manufacturers')
def export_manufacturers():
    """Export manufacturers as CSV"""
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    manufacturers = load_manufacturers()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Company Name', 'Email', 'License Number', 'GST Number', 'Status', 'Created Date', 'Approved Date'])
    
    # Write data
    for manufacturer in manufacturers:
        writer.writerow([
            manufacturer.get('company_name', ''),
            manufacturer.get('email', ''),
            manufacturer.get('license_number', ''),
            manufacturer.get('gst_number', ''),
            'Approved' if manufacturer.get('approved') else 'Pending',
            manufacturer.get('created_at', '')[:10],
            manufacturer.get('approved_at', '')[:10] if manufacturer.get('approved_at') else ''
        ])
    
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=medlock_manufacturers.csv'}
    )

@app.route('/admin/export/batches')
def export_batches():
    """Export batches as CSV"""
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    batches = load_batches()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Batch ID', 'Medicine Name', 'Manufacturer', 'Manufacturing Date', 'Expiry Date', 'Dosage', 'Scan Count', 'Upload Date', 'Security Level'])
    
    # Write data
    for batch in batches:
        writer.writerow([
            batch.get('batch_id', ''),
            batch.get('medicine_name', ''),
            batch.get('manufacturer_name', ''),
            batch.get('manufacturing_date', ''),
            batch.get('expiry_date', ''),
            batch.get('dosage', ''),
            batch.get('scan_count', 0),
            batch.get('upload_date', '')[:10],
            batch.get('security_level', 'standard')
        ])
    
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=medlock_batches.csv'}
    )

@app.route('/download-project')
def download_project():
    """Download the entire project as a zip file"""
    
    # Create a temporary file for the zip
    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
    
    # Files and directories to include in the zip
    files_to_include = [
        'app.py',
        'main.py',
        'ai_fraud_detector.py',
        'blockchain_integration.py',
        'create_test_data.py',
        'generate_demo_qr.py',
        'replit.md',
        'pyproject.toml',
        'uv.lock',
        'manufacturers.json',
        'batches.json',
        'scan_logs.json',
        'templates/',
        'static/',
        'data/',
        'logs/',
        'qr/'
    ]
    
    try:
        with zipfile.ZipFile(temp_zip.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for item in files_to_include:
                if os.path.exists(item):
                    if os.path.isfile(item):
                        zipf.write(item, item)
                    elif os.path.isdir(item):
                        # Add directory and all its contents
                        for root, dirs, files in os.walk(item):
                            for file in files:
                                file_path = os.path.join(root, file)
                                zipf.write(file_path, file_path)
        
        # Send the zip file
        return send_file(
            temp_zip.name,
            as_attachment=True,
            download_name=f'medlock_project_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip',
            mimetype='application/zip'
        )
        
    except Exception as e:
        flash(f'Error creating zip file: {str(e)}', 'error')
        return redirect(url_for('index'))
    
    finally:
        # Clean up the temporary file
        try:
            os.unlink(temp_zip.name)
        except:
            pass

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
