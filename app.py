#!/usr/bin/env python3
"""
VaultGuard Enhanced - Advanced Password Manager
Phase 1 Implementation with Enhanced Security Features

Features:
- AES-256 encryption with PBKDF2 key derivation
- Enhanced breach monitoring and notifications
- IST timezone support
- Advanced security analytics
- Proactive security alerts
- Session management with proper timeouts
"""

import os
import json
import hashlib
import sqlite3
import secrets
import logging
from datetime import datetime, timedelta
import pytz
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from functools import wraps

# Flask imports with error handling
try:
    from flask import Flask, request, jsonify, session, render_template_string, send_from_directory
    from flask_session import Session
    from werkzeug.security import generate_password_hash, check_password_hash
except ImportError as e:
    print(f"Error: Required packages not installed. Run: pip install flask flask-session")
    print(f"Missing: {e}")
    exit(1)

# Cryptography imports with error handling  
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
except ImportError as e:
    print(f"Error: Cryptography package not installed. Run: pip install cryptography")
    print(f"Missing: {e}")
    exit(1)

# ===== CONFIGURATION =====
@dataclass
class Config:
    """Application configuration with enhanced security settings"""
    SECRET_KEY: str = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    DATABASE_PATH: str = 'vaultguard_enhanced.db'
    SESSION_TIMEOUT: int = 15 * 60  # 15 minutes
    MAX_LOGIN_ATTEMPTS: int = 5
    LOGIN_ATTEMPT_WINDOW: int = 15 * 60  # 15 minutes
    PBKDF2_ITERATIONS: int = 600000  # Enhanced from 100k to 600k
    TIMEZONE: str = 'Asia/Kolkata'  # IST timezone
    DEBUG: bool = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    HOST: str = os.environ.get('HOST', '127.0.0.1')
    PORT: int = int(os.environ.get('PORT', 5000))

config = Config()

# ===== LOGGING SETUP =====
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vaultguard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ===== TIMEZONE HANDLING =====
IST = pytz.timezone(config.TIMEZONE)

def get_ist_time() -> datetime:
    """Get current time in IST timezone"""
    return datetime.now(IST)

def format_ist_time(dt: datetime) -> str:
    """Format datetime for IST display"""
    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt).astimezone(IST)
    return dt.strftime('%Y-%m-%d %H:%M:%S IST')

# ===== ENHANCED ENCRYPTION =====
class AdvancedEncryption:
    """Enhanced encryption with PBKDF2 and AES-256"""
    
    @staticmethod
    def generate_salt() -> str:
        """Generate cryptographically secure salt"""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    
    @staticmethod
    def derive_key(password: str, salt: str) -> bytes:
        """Derive encryption key using PBKDF2 with 600k iterations"""
        salt_bytes = base64.urlsafe_b64decode(salt.encode())
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=config.PBKDF2_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    @staticmethod
    def encrypt_data(data: str, password: str, salt: str) -> str:
        """Encrypt data with AES-256"""
        try:
            key = AdvancedEncryption.derive_key(password, salt)
            f = Fernet(key)
            encrypted_data = f.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    @staticmethod
    def decrypt_data(encrypted_data: str, password: str, salt: str) -> str:
        """Decrypt data with AES-256"""
        try:
            key = AdvancedEncryption.derive_key(password, salt)
            f = Fernet(key)
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = f.decrypt(encrypted_bytes)
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise

# ===== ENHANCED DATABASE =====
class AdvancedDatabase:
    """Enhanced database with security features"""
    
    def __init__(self, db_path: str = config.DATABASE_PATH):
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self) -> sqlite3.Connection:
        """Get database connection with enhanced settings"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        conn.execute('PRAGMA journal_mode = WAL')
        conn.execute('PRAGMA synchronous = FULL')
        return conn
    
    def init_database(self):
        """Initialize enhanced database schema"""
        with self.get_connection() as conn:
            # Users table with security tracking
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP,
                    settings TEXT DEFAULT '{}',
                    UNIQUE(username)
                )
            ''')
            
            # Enhanced vault entries
            conn.execute('''
                CREATE TABLE IF NOT EXISTS vault_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    site_name TEXT NOT NULL,
                    site_url TEXT,
                    username TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    notes TEXT,
                    strength_score INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_accessed TIMESTAMP,
                    access_count INTEGER DEFAULT 0,
                    breach_detected BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')
            
            # Security notifications table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS security_notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    notification_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    priority TEXT DEFAULT 'medium',
                    acknowledged BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    data TEXT DEFAULT '{}',
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')
            
            # Security events log
            conn.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    event_type TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for performance
            conn.execute('CREATE INDEX IF NOT EXISTS idx_vault_user_id ON vault_entries(user_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON security_notifications(user_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_user_id ON security_events(user_id)')
            
            conn.commit()
            logger.info("Enhanced database initialized successfully")

# ===== SECURITY MANAGER =====
class SecurityManager:
    """Enhanced security management"""
    
    def __init__(self, db: AdvancedDatabase):
        self.db = db
    
    def log_security_event(self, user_id: Optional[int], event_type: str, 
                          ip_address: str = None, user_agent: str = None, 
                          details: str = None):
        """Log security events"""
        try:
            with self.db.get_connection() as conn:
                conn.execute('''
                    INSERT INTO security_events (user_id, event_type, ip_address, user_agent, details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, event_type, ip_address, user_agent, details))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
    
    def check_rate_limit(self, username: str) -> Tuple[bool, Optional[datetime]]:
        """Enhanced rate limiting with account lockout"""
        try:
            with self.db.get_connection() as conn:
                user_data = conn.execute(
                    'SELECT login_attempts, locked_until FROM users WHERE username = ?',
                    (username,)
                ).fetchone()
                
                if not user_data:
                    return True, None
                
                locked_until = user_data['locked_until']
                if locked_until:
                    locked_dt = datetime.fromisoformat(locked_until)
                    if get_ist_time() < locked_dt:
                        return False, locked_dt
                    else:
                        # Unlock account
                        conn.execute(
                            'UPDATE users SET login_attempts = 0, locked_until = NULL WHERE username = ?',
                            (username,)
                        )
                        conn.commit()
                
                return True, None
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return False, None
    
    def record_failed_attempt(self, username: str):
        """Record failed login attempt"""
        try:
            with self.db.get_connection() as conn:
                current_attempts = conn.execute(
                    'SELECT login_attempts FROM users WHERE username = ?',
                    (username,)
                ).fetchone()
                
                if current_attempts:
                    new_attempts = current_attempts['login_attempts'] + 1
                    locked_until = None
                    
                    if new_attempts >= config.MAX_LOGIN_ATTEMPTS:
                        locked_until = (get_ist_time() + timedelta(minutes=15)).isoformat()
                        logger.warning(f"Account locked for user: {username}")
                    
                    conn.execute('''
                        UPDATE users SET login_attempts = ?, locked_until = ?
                        WHERE username = ?
                    ''', (new_attempts, locked_until, username))
                    conn.commit()
        except Exception as e:
            logger.error(f"Failed to record login attempt: {e}")
    
    def reset_failed_attempts(self, username: str):
        """Reset failed login attempts on successful login"""
        try:
            with self.db.get_connection() as conn:
                conn.execute('''
                    UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = ?
                    WHERE username = ?
                ''', (get_ist_time().isoformat(), username))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to reset login attempts: {e}")
    
    def analyze_password_strength(self, password: str) -> Dict[str, Any]:
        """Advanced password strength analysis"""
        import re
        
        length = len(password)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_numbers = bool(re.search(r'\d', password))
        has_symbols = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?~`]', password))
        
        # Calculate entropy
        charset = 0
        if has_lower: charset += 26
        if has_upper: charset += 26  
        if has_numbers: charset += 10
        if has_symbols: charset += 32
        
        entropy = length * (charset.bit_length() - 1) if charset > 0 else 0
        
        # Weakness checks
        weak_patterns = [
            r'password', r'123456', r'qwerty', r'abc123', r'admin',
            r'(.)\1{3,}',  # repeated characters
            r'(012|123|234|345|456|567|678|789|890)+',  # sequential numbers
        ]
        
        has_weak_pattern = any(re.search(pattern, password, re.IGNORECASE) for pattern in weak_patterns)
        
        # Calculate score (0-100)
        score = 0
        
        # Length scoring
        if length >= 16: score += 35
        elif length >= 12: score += 25
        elif length >= 8: score += 15
        elif length >= 6: score += 5
        
        # Character variety
        if has_upper: score += 5
        if has_lower: score += 5  
        if has_numbers: score += 5
        if has_symbols: score += 10
        
        # Entropy bonus
        if entropy >= 100: score += 25
        elif entropy >= 80: score += 20
        elif entropy >= 60: score += 15
        elif entropy >= 40: score += 10
        elif entropy >= 20: score += 5
        
        # Penalties
        if has_weak_pattern: score -= 20
        if length < 8: score -= 10
        
        score = max(0, min(100, score))
        
        # Determine strength level
        if score >= 90: strength = 'fortress'
        elif score >= 80: strength = 'military'
        elif score >= 70: strength = 'strong'
        elif score >= 50: strength = 'good'
        elif score >= 30: strength = 'fair'
        elif score >= 15: strength = 'weak'
        else: strength = 'critical'
        
        return {
            'score': score,
            'strength': strength,
            'entropy': entropy,
            'length': length,
            'has_upper': has_upper,
            'has_lower': has_lower,
            'has_numbers': has_numbers,
            'has_symbols': has_symbols,
            'has_weak_pattern': has_weak_pattern
        }

# ===== FLASK APPLICATION =====
app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_THRESHOLD'] = 100

# Initialize session
Session(app)

# Initialize components
db = AdvancedDatabase()
security_manager = SecurityManager(db)
encryption = AdvancedEncryption()

# ===== AUTHENTICATION DECORATORS =====
def login_required(f):
    """Enhanced login required decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or 'username' not in session:
            return jsonify({'error': 'Authentication required', 'authenticated': False}), 401
        
        # Check session timeout
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if get_ist_time() - last_activity > timedelta(seconds=config.SESSION_TIMEOUT):
                session.clear()
                return jsonify({'error': 'Session expired', 'authenticated': False}), 401
        
        # Update last activity
        session['last_activity'] = get_ist_time().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def rate_limit_check(f):
    """Rate limiting decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = request.json.get('username') if request.json else None
        if username:
            allowed, locked_until = security_manager.check_rate_limit(username)
            if not allowed:
                return jsonify({
                    'error': f'Account locked until {format_ist_time(locked_until)}',
                    'locked_until': locked_until.isoformat() if locked_until else None
                }), 429
        return f(*args, **kwargs)
    return decorated_function

# ===== ROUTES =====

@app.route('/')
def index():
    """Serve the enhanced main page"""
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "VaultGuard Enhanced - index.html not found", 404

@app.route('/style.css')
def styles():
    """Serve CSS with proper MIME type"""
    try:
        return send_from_directory('.', 'style.css', mimetype='text/css')
    except FileNotFoundError:
        return "CSS file not found", 404

@app.route('/script.js')
def scripts():
    """Serve JavaScript with proper MIME type"""
    try:
        return send_from_directory('.', 'script.js', mimetype='application/javascript')
    except FileNotFoundError:
        return "JavaScript file not found", 404

# ===== AUTHENTICATION ENDPOINTS =====

@app.route('/auth/register', methods=['POST'])
@rate_limit_check
def register():
    """Enhanced user registration"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
            
        username = data.get('username', '').strip().lower()
        master_password = data.get('master_password', '')
        
        if not username or not master_password:
            return jsonify({'error': 'Username and master password are required'}), 400
        
        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
            
        if len(master_password) < 8:
            return jsonify({'error': 'Master password must be at least 8 characters'}), 400
        
        # Analyze master password strength
        strength_analysis = security_manager.analyze_password_strength(master_password)
        if strength_analysis['score'] < 30:
            return jsonify({
                'error': 'Master password is too weak',
                'strength_analysis': strength_analysis
            }), 400
        
        # Check if user exists
        with db.get_connection() as conn:
            existing_user = conn.execute(
                'SELECT id FROM users WHERE username = ?', (username,)
            ).fetchone()
            
            if existing_user:
                return jsonify({'error': 'Username already exists'}), 409
            
            # Create new user
            salt = encryption.generate_salt()
            password_hash = generate_password_hash(master_password)
            
            conn.execute('''
                INSERT INTO users (username, password_hash, salt, created_at, settings)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                username, 
                password_hash, 
                salt,
                get_ist_time().isoformat(),
                json.dumps({
                    'breach_alerts': True,
                    'password_age_warnings': True,
                    'email_notifications': False,
                    'phone_notifications': False,
                    'security_scanning': True
                })
            ))
            conn.commit()
            
            # Log security event
            security_manager.log_security_event(
                None, 'user_registered', 
                request.remote_addr, 
                request.headers.get('User-Agent'),
                f'User {username} registered'
            )
            
            logger.info(f"New user registered: {username}")
            
            return jsonify({
                'success': True,
                'message': 'Registration successful',
                'strength_analysis': strength_analysis
            })
            
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/auth/login', methods=['POST'])
@rate_limit_check
def login():
    """Enhanced user login"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
            
        username = data.get('username', '').strip().lower()
        master_password = data.get('master_password', '')
        
        if not username or not master_password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        with db.get_connection() as conn:
            user_data = conn.execute('''
                SELECT id, username, password_hash, salt, login_attempts, locked_until
                FROM users WHERE username = ?
            ''', (username,)).fetchone()
            
            if not user_data:
                security_manager.log_security_event(
                    None, 'login_failed_no_user',
                    request.remote_addr,
                    request.headers.get('User-Agent'),
                    f'Login attempt for non-existent user: {username}'
                )
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Check password
            if not check_password_hash(user_data['password_hash'], master_password):
                security_manager.record_failed_attempt(username)
                security_manager.log_security_event(
                    user_data['id'], 'login_failed_wrong_password',
                    request.remote_addr,
                    request.headers.get('User-Agent'),
                    f'Failed login attempt for user: {username}'
                )
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Successful login
            security_manager.reset_failed_attempts(username)
            
            # Set session
            session.permanent = False
            session['user_id'] = user_data['id']
            session['username'] = user_data['username']
            session['salt'] = user_data['salt']
            session['last_activity'] = get_ist_time().isoformat()
            session['login_time'] = get_ist_time().isoformat()
            
            # Log successful login
            security_manager.log_security_event(
                user_data['id'], 'login_success',
                request.remote_addr,
                request.headers.get('User-Agent'),
                f'Successful login for user: {username}'
            )
            
            logger.info(f"User logged in: {username}")
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'username': user_data['username'],
                'login_time': format_ist_time(get_ist_time())
            })
            
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/auth/logout', methods=['POST'])
@login_required
def logout():
    """Enhanced logout"""
    try:
        username = session.get('username')
        user_id = session.get('user_id')
        
        # Log logout
        security_manager.log_security_event(
            user_id, 'logout',
            request.remote_addr,
            request.headers.get('User-Agent'),
            f'User {username} logged out'
        )
        
        session.clear()
        logger.info(f"User logged out: {username}")
        
        return jsonify({'success': True, 'message': 'Logged out successfully'})
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500

@app.route('/api/session-check', methods=['GET'])
def session_check():
    """Check if user has valid session"""
    try:
        if 'user_id' not in session or 'username' not in session:
            return jsonify({'authenticated': False})
        
        # Check session timeout
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if get_ist_time() - last_activity > timedelta(seconds=config.SESSION_TIMEOUT):
                session.clear()
                return jsonify({'authenticated': False, 'reason': 'session_expired'})
        
        # Update last activity
        session['last_activity'] = get_ist_time().isoformat()
        
        return jsonify({
            'authenticated': True,
            'username': session['username'],
            'login_time': session.get('login_time')
        })
        
    except Exception as e:
        logger.error(f"Session check error: {e}")
        return jsonify({'authenticated': False, 'error': 'Session check failed'})

# ===== VAULT ENDPOINTS =====

@app.route('/api/vault', methods=['GET'])
@login_required
def get_vault_entries():
    """Get all vault entries for the user"""
    try:
        user_id = session['user_id']
        
        with db.get_connection() as conn:
            entries = conn.execute('''
                SELECT id, site_name, site_url, username, encrypted_password, notes,
                       strength_score, created_at, updated_at, last_accessed, access_count,
                       breach_detected
                FROM vault_entries 
                WHERE user_id = ?
                ORDER BY created_at DESC
            ''', (user_id,)).fetchall()
            
            vault_entries = []
            for entry in entries:
                try:
                    # Don't decrypt password for list view (security)
                    vault_entry = {
                        'id': entry['id'],
                        'site_name': entry['site_name'],
                        'site_url': entry['site_url'],
                        'username': entry['username'],
                        'notes': entry['notes'],
                        'strength_score': entry['strength_score'],
                        'created_at': entry['created_at'],
                        'updated_at': entry['updated_at'],
                        'last_accessed': entry['last_accessed'],
                        'access_count': entry['access_count'],
                        'breach_detected': entry['breach_detected'],
                        'password_length': len(entry['encrypted_password']) // 4  # Rough estimate
                    }
                    vault_entries.append(vault_entry)
                except Exception as e:
                    logger.error(f"Error processing vault entry {entry['id']}: {e}")
                    continue
            
            return jsonify({
                'success': True,
                'entries': vault_entries,
                'count': len(vault_entries)
            })
            
    except Exception as e:
        logger.error(f"Get vault entries error: {e}")
        return jsonify({'error': 'Failed to retrieve vault entries'}), 500

@app.route('/api/vault', methods=['POST'])
@login_required
def save_vault_entry():
    """Save a new vault entry"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        user_id = session['user_id']
        salt = session['salt']
        
        # Extract and validate data
        site_name = data.get('site_name', '').strip()
        site_url = data.get('site_url', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        notes = data.get('notes', '').strip()
        master_password = data.get('master_password', '')
        
        if not all([site_name, username, password]):
            return jsonify({'error': 'Site name, username, and password are required'}), 400
        
        if not master_password:
            return jsonify({'error': 'Master password required for encryption'}), 400
        
        # Analyze password strength
        strength_analysis = security_manager.analyze_password_strength(password)
        
        # Encrypt the password
        encrypted_password = encryption.encrypt_data(password, master_password, salt)
        
        with db.get_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO vault_entries (
                    user_id, site_name, site_url, username, encrypted_password,
                    notes, strength_score, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, site_name, site_url, username, encrypted_password,
                notes, strength_analysis['score'], 
                get_ist_time().isoformat(), get_ist_time().isoformat()
            ))
            
            entry_id = cursor.lastrowid
            conn.commit()
            
            # Log security event
            security_manager.log_security_event(
                user_id, 'vault_entry_created',
                request.remote_addr,
                request.headers.get('User-Agent'),
                f'Created vault entry for {site_name}'
            )
            
            # Check for potential security issues
            if strength_analysis['score'] < 50:
                # Add weak password notification
                conn.execute('''
                    INSERT INTO security_notifications (
                        user_id, notification_type, title, message, priority, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    user_id, 'weak', 'Weak Password Detected',
                    f'The password for {site_name} has a low strength score of {strength_analysis["score"]}/100. Consider generating a stronger password.',
                    'medium', get_ist_time().isoformat()
                ))
                conn.commit()
            
            logger.info(f"Vault entry created for user {session['username']}: {site_name}")
            
            return jsonify({
                'success': True,
                'message': 'Entry saved successfully',
                'entry_id': entry_id,
                'strength_analysis': strength_analysis
            })
            
    except Exception as e:
        logger.error(f"Save vault entry error: {e}")
        return jsonify({'error': 'Failed to save vault entry'}), 500

@app.route('/api/vault/<int:entry_id>', methods=['DELETE'])
@login_required
def delete_vault_entry(entry_id):
    """Delete a vault entry"""
    try:
        user_id = session['user_id']
        
        with db.get_connection() as conn:
            # Check if entry exists and belongs to user
            entry = conn.execute('''
                SELECT site_name FROM vault_entries 
                WHERE id = ? AND user_id = ?
            ''', (entry_id, user_id)).fetchone()
            
            if not entry:
                return jsonify({'error': 'Entry not found'}), 404
            
            # Delete the entry
            conn.execute('''
                DELETE FROM vault_entries 
                WHERE id = ? AND user_id = ?
            ''', (entry_id, user_id))
            
            conn.commit()
            
            # Log security event
            security_manager.log_security_event(
                user_id, 'vault_entry_deleted',
                request.remote_addr,
                request.headers.get('User-Agent'),
                f'Deleted vault entry for {entry["site_name"]}'
            )
            
            logger.info(f"Vault entry deleted for user {session['username']}: {entry['site_name']}")
            
            return jsonify({
                'success': True,
                'message': 'Entry deleted successfully'
            })
            
    except Exception as e:
        logger.error(f"Delete vault entry error: {e}")
        return jsonify({'error': 'Failed to delete vault entry'}), 500

@app.route('/api/vault/<int:entry_id>/decrypt', methods=['POST'])
@login_required
def decrypt_vault_entry(entry_id):
    """Decrypt a specific vault entry password"""
    try:
        data = request.get_json()
        master_password = data.get('master_password', '') if data else ''
        
        if not master_password:
            return jsonify({'error': 'Master password required'}), 400
        
        user_id = session['user_id']
        salt = session['salt']
        
        with db.get_connection() as conn:
            entry = conn.execute('''
                SELECT site_name, encrypted_password, access_count
                FROM vault_entries 
                WHERE id = ? AND user_id = ?
            ''', (entry_id, user_id)).fetchone()
            
            if not entry:
                return jsonify({'error': 'Entry not found'}), 404
            
            # Decrypt password
            decrypted_password = encryption.decrypt_data(
                entry['encrypted_password'], master_password, salt
            )
            
            # Update access tracking
            conn.execute('''
                UPDATE vault_entries 
                SET access_count = ?, last_accessed = ?
                WHERE id = ?
            ''', (entry['access_count'] + 1, get_ist_time().isoformat(), entry_id))
            
            conn.commit()
            
            # Log access
            security_manager.log_security_event(
                user_id, 'vault_entry_accessed',
                request.remote_addr,
                request.headers.get('User-Agent'),
                f'Accessed vault entry for {entry["site_name"]}'
            )
            
            return jsonify({
                'success': True,
                'password': decrypted_password,
                'access_time': format_ist_time(get_ist_time())
            })
            
    except Exception as e:
        logger.error(f"Decrypt vault entry error: {e}")
        return jsonify({'error': 'Failed to decrypt entry or invalid master password'}), 500

# ===== NOTIFICATION ENDPOINTS =====

@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    """Get security notifications for the user"""
    try:
        user_id = session['user_id']
        
        with db.get_connection() as conn:
            notifications = conn.execute('''
                SELECT id, notification_type, title, message, priority,
                       acknowledged, created_at, data
                FROM security_notifications 
                WHERE user_id = ? AND acknowledged = FALSE
                ORDER BY created_at DESC
                LIMIT 50
            ''', (user_id,)).fetchall()
            
            notification_list = []
            for notif in notifications:
                notification_data = {
                    'id': notif['id'],
                    'type': notif['notification_type'],
                    'title': notif['title'],
                    'message': notif['message'],
                    'priority': notif['priority'],
                    'acknowledged': notif['acknowledged'],
                    'created_at': notif['created_at'],
                    'data': json.loads(notif['data']) if notif['data'] else {}
                }
                notification_list.append(notification_data)
            
            return jsonify({
                'success': True,
                'notifications': notification_list,
                'count': len(notification_list)
            })
            
    except Exception as e:
        logger.error(f"Get notifications error: {e}")
        return jsonify({'error': 'Failed to retrieve notifications'}), 500

@app.route('/api/notifications/<int:notification_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_notification(notification_id):
    """Acknowledge a security notification"""
    try:
        user_id = session['user_id']
        
        with db.get_connection() as conn:
            # Check if notification exists and belongs to user
            notification = conn.execute('''
                SELECT id FROM security_notifications 
                WHERE id = ? AND user_id = ?
            ''', (notification_id, user_id)).fetchone()
            
            if not notification:
                return jsonify({'error': 'Notification not found'}), 404
            
            # Mark as acknowledged
            conn.execute('''
                UPDATE security_notifications 
                SET acknowledged = TRUE
                WHERE id = ? AND user_id = ?
            ''', (notification_id, user_id))
            
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Notification acknowledged'
            })
            
    except Exception as e:
        logger.error(f"Acknowledge notification error: {e}")
        return jsonify({'error': 'Failed to acknowledge notification'}), 500

# ===== SETTINGS ENDPOINTS =====

@app.route('/api/settings', methods=['GET'])
@login_required
def get_settings():
    """Get user settings"""
    try:
        user_id = session['user_id']
        
        with db.get_connection() as conn:
            user_data = conn.execute('''
                SELECT settings FROM users WHERE id = ?
            ''', (user_id,)).fetchone()
            
            if not user_data:
                return jsonify({'error': 'User not found'}), 404
            
            settings = json.loads(user_data['settings']) if user_data['settings'] else {}
            
            return jsonify({
                'success': True,
                'settings': settings
            })
            
    except Exception as e:
        logger.error(f"Get settings error: {e}")
        return jsonify({'error': 'Failed to retrieve settings'}), 500

@app.route('/api/settings', methods=['POST'])
@login_required
def save_settings():
    """Save user settings"""
    try:
        data = request.get_json()
        if not data or 'settings' not in data:
            return jsonify({'error': 'Invalid settings data'}), 400
        
        user_id = session['user_id']
        settings = data['settings']
        
        with db.get_connection() as conn:
            conn.execute('''
                UPDATE users SET settings = ? WHERE id = ?
            ''', (json.dumps(settings), user_id))
            
            conn.commit()
            
            # Log settings change
            security_manager.log_security_event(
                user_id, 'settings_updated',
                request.remote_addr,
                request.headers.get('User-Agent'),
                'User settings updated'
            )
            
            return jsonify({
                'success': True,
                'message': 'Settings saved successfully'
            })
            
    except Exception as e:
        logger.error(f"Save settings error: {e}")
        return jsonify({'error': 'Failed to save settings'}), 500

# ===== ERROR HANDLERS =====

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# ===== MAIN APPLICATION =====

if __name__ == '__main__':
    logger.info("="*60)
    logger.info("🔐 VaultGuard Enhanced - Phase 1 Starting")
    logger.info("="*60)
    logger.info(f"🌐 Host: {config.HOST}:{config.PORT}")
    logger.info(f"🕐 Timezone: {config.TIMEZONE}")
    logger.info(f"🔒 PBKDF2 Iterations: {config.PBKDF2_ITERATIONS:,}")
    logger.info(f"⏰ Session Timeout: {config.SESSION_TIMEOUT//60} minutes")
    logger.info(f"🚫 Max Login Attempts: {config.MAX_LOGIN_ATTEMPTS}")
    logger.info("="*60)
    
    try:
        app.run(
            host=config.HOST,
            port=config.PORT,
            debug=config.DEBUG,
            threaded=True
        )
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        exit(1)
