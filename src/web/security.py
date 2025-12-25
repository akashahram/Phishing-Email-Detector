# Security Middleware and Utilities
from flask import request, jsonify
from functools import wraps
import re


class SecurityMiddleware:
    """Security middleware for Flask application"""
    
    def __init__(self, app):
        self.app = app
        self.setup_security_headers()
        self.setup_input_validation()
    
    def setup_security_headers(self):
        """Add security headers to all responses"""
        @self.app.after_request
        def add_security_headers(response):
            headers = self.app.config.get('SECURE_HEADERS', {})
            for header, value in headers.items():
                response.headers[header] = value
            return response
    
    def setup_input_validation(self):
        """Set up input validation"""
        @self.app.before_request
        def validate_content_length():
            # Check content length
            max_length = self.app.config.get('MAX_CONTENT_LENGTH', 10 * 1024 * 1024)
            content_length = request.content_length
            
            if content_length and content_length > max_length:
                return jsonify({
                    'error': 'Request too large',
                    'message': f'Maximum request size is {max_length / (1024*1024)}MB'
                }), 413


def sanitize_input(text, max_length=None):
    """Sanitize user input"""
    if not text:
        return text
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Limit length
    if max_length and len(text) > max_length:
        text = text[:max_length]
    
    return text


def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password_strength(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    return True, None


def validate_api_key_format(api_key):
    """Validate API key format"""
    return api_key.startswith('sk_') and len(api_key) > 20


def require_https(f):
    """Decorator to require HTTPS in production"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import current_app
        
        if not current_app.config.get('DEBUG', False):
            if not request.is_secure:
                return jsonify({
                    'error': 'HTTPS required',
                    'message': 'This endpoint requires a secure connection'
                }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function


def validate_file_upload(file):
    """Validate uploaded file"""
    if not file:
        return False, "No file provided"
    
    # Check filename
    if not file.filename:
        return False, "No filename provided"
    
    # Check allowed extensions
    allowed_extensions = {'.eml', '.msg', '.txt'}
    file_ext = '.' + file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    
    if file_ext not in allowed_extensions:
        return False, f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}"
    
    return True, None


def get_client_ip():
    """Get client IP address, accounting for proxies"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr


def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal"""
    # Remove path components
    filename = filename.split('/')[-1].split('\\')[-1]
    
    # Remove dangerous characters
    filename = re.sub(r'[^\w\s.-]', '', filename)
    
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:250] + ('.' + ext if ext else '')
    
    return filename
