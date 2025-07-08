import os
import json
import uuid
import qrcode
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "your-secret-key-for-demo")

# Configuration
UPLOAD_FOLDER = 'static/uploads'
QR_FOLDER = 'static/qr_codes'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QR_FOLDER, exist_ok=True)

# Admin credentials (hardcoded for demo)
ADMIN_EMAIL = "admin@medlock.com"
ADMIN_PASSWORD = "admin123"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_manufacturers():
    try:
        with open('manufacturers.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_manufacturers(manufacturers):
    with open('manufacturers.json', 'w') as f:
        json.dump(manufacturers, f, indent=2)

def load_batches():
    try:
        with open('batches.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_batches(batches):
    with open('batches.json', 'w') as f:
        json.dump(batches, f, indent=2)

def generate_qr_code(batch_id):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    verify_url = f"http://localhost:5000/verify/{batch_id}"
    qr.add_data(verify_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    qr_filename = f"{batch_id}.png"
    qr_path = os.path.join(QR_FOLDER, qr_filename)
    img.save(qr_path)
    return qr_filename

@app.route('/')
def index():
    return render_template('index.html')

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
            
            # Create new manufacturer
            new_manufacturer = {
                'id': str(uuid.uuid4()),
                'company_name': company_name,
                'email': email,
                'gst_number': gst_number,
                'license_number': license_number,
                'password_hash': generate_password_hash(password),
                'license_file': filename,
                'approved': False,
                'created_at': datetime.now().isoformat()
            }
            
            manufacturers.append(new_manufacturer)
            save_manufacturers(manufacturers)
            
            flash('Registration successful! Your account is under review.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid file type. Please upload PDF, PNG, JPG, JPEG, or GIF files.', 'error')
    
    return render_template('register.html')

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
    return render_template('admin_dashboard.html', manufacturers=manufacturers)

@app.route('/admin/approve/<manufacturer_id>')
def approve_manufacturer(manufacturer_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    manufacturers = load_manufacturers()
    for manufacturer in manufacturers:
        if manufacturer['id'] == manufacturer_id:
            manufacturer['approved'] = True
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
        batch_id = request.form['batch_id']
        medicine_name = request.form['medicine_name']
        expiry_date = request.form['expiry_date']
        
        # Check if batch ID already exists
        batches = load_batches()
        for batch in batches:
            if batch['batch_id'] == batch_id:
                flash('Batch ID already exists', 'error')
                return redirect(request.url)
        
        # Generate QR code
        qr_filename = generate_qr_code(batch_id)
        
        # Create new batch
        new_batch = {
            'id': str(uuid.uuid4()),
            'batch_id': batch_id,
            'medicine_name': medicine_name,
            'expiry_date': expiry_date,
            'manufacturer_id': session['manufacturer_id'],
            'company_name': session['company_name'],
            'qr_code': qr_filename,
            'created_at': datetime.now().isoformat()
        }
        
        batches.append(new_batch)
        save_batches(batches)
        
        flash('Batch uploaded successfully!', 'success')
        return render_template('batch_upload.html', batch=new_batch, show_qr=True)
    
    return render_template('batch_upload.html')

@app.route('/verify/<batch_id>')
def verify_batch(batch_id):
    batches = load_batches()
    
    for batch in batches:
        if batch['batch_id'] == batch_id:
            return render_template('verify.html', batch=batch, genuine=True)
    
    return render_template('verify.html', batch_id=batch_id, genuine=False)

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
