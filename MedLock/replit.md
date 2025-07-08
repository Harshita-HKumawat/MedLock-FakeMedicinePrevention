# replit.md

## Overview

MedLock is a Flask-based web application designed as a medicine authenticity platform. It enables pharmaceutical manufacturers to register, upload medicine batches, and generate QR codes for verification. The system includes an admin panel for manufacturer approval and a public verification system for customers to check medicine authenticity.

## System Architecture

### Frontend Architecture
- **Template Engine**: Jinja2 templates with Flask
- **CSS Framework**: Bootstrap (dark theme via CDN)
- **Icons**: Font Awesome 6.0.0
- **Client-side**: Vanilla HTML/CSS/JS with Bootstrap components
- **Theme**: Dark theme implementation using bootstrap-agent-dark-theme

### Backend Architecture
- **Framework**: Flask (Python web framework)
- **Session Management**: Flask sessions with server-side storage
- **Authentication**: Password hashing using Werkzeug security utilities
- **File Handling**: Werkzeug secure filename utilities
- **Logging**: Python's built-in logging module

### Data Storage Solutions
- **Primary Storage**: JSON file-based storage
  - `manufacturers.json`: Stores manufacturer registration data
  - `batches.json`: Stores medicine batch information
- **File Storage**: Local filesystem for uploaded documents and QR codes
  - `static/uploads/`: License documents
  - `static/qr_codes/`: Generated QR code images

### Authentication and Authorization
- **Admin Access**: Hardcoded credentials (demo setup)
  - Email: admin@medlock.com
  - Password: admin123
- **Manufacturer Authentication**: Email/password with hashed passwords
- **Session-based**: Flask sessions for maintaining login state
- **Authorization Levels**: Admin and Manufacturer roles

## Key Components

### User Management
- **Manufacturer Registration**: Multi-step process with document upload
- **Admin Approval Workflow**: Pending → Approved status for manufacturers
- **Login/Logout System**: Separate flows for admins and manufacturers

### Batch Management
- **Batch Upload**: Manufacturers can create medicine batches
- **QR Code Generation**: Automatic QR code creation using `qrcode` library
- **Batch Verification**: Public verification system via QR codes

### File Management
- **Document Upload**: Secure file handling for license documents
- **File Validation**: Restricted to specific file types (PDF, PNG, JPG, JPEG, GIF)
- **Static File Serving**: Flask static file serving for uploads and QR codes

## Data Flow

1. **Manufacturer Registration**:
   - User submits registration form with license document
   - Data stored in `manufacturers.json` with "pending" status
   - Admin reviews and approves/rejects

2. **Batch Creation**:
   - Approved manufacturer uploads batch details
   - System generates unique batch ID
   - QR code created linking to verification URL
   - Batch data stored in `batches.json`

3. **Verification Process**:
   - Public scans QR code or enters batch ID
   - System looks up batch in `batches.json`
   - Returns verification status and batch details

## External Dependencies

### Python Packages
- **Flask**: Web framework
- **qrcode**: QR code generation
- **Werkzeug**: Security utilities and file handling
- **Pillow**: Image processing (dependency of qrcode)

### CDN Dependencies
- **Bootstrap**: `bootstrap-agent-dark-theme.min.css`
- **Font Awesome**: `font-awesome/6.0.0/css/all.min.css`

### Environment Variables
- `SESSION_SECRET`: Flask session secret key (defaults to demo key)

## Deployment Strategy

### Current Setup
- **Development Mode**: Flask debug mode enabled
- **Host Configuration**: Bound to `0.0.0.0:5000` for container compatibility
- **Static Files**: Served directly by Flask (development setup)

### File Structure
```
/
├── app.py              # Main Flask application
├── main.py             # Entry point
├── manufacturers.json  # Manufacturer data
├── batches.json       # Batch data
├── templates/         # Jinja2 templates
└── static/
    ├── uploads/       # License documents
    └── qr_codes/      # Generated QR codes
```

### Scalability Considerations
- File-based storage suitable for small to medium scale
- JSON storage may need migration to proper database for production
- Static file serving should use CDN or web server in production

## Changelog

```
Changelog:
- July 08, 2025. Initial setup
```

## User Preferences

```
Preferred communication style: Simple, everyday language.
```