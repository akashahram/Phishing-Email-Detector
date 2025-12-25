# Authentication Module
from functools import wraps
from flask import request, jsonify, g
from datetime import datetime, timedelta
import jwt
from werkzeug.security import generate_password_hash
from sqlalchemy.orm import Session
from models import User, APIKey, AuditLog
import secrets
import hashlib


class AuthManager:
    """Manages authentication and authorization"""
    
    def __init__(self, app, db_session):
        self.app = app
        self.db = db_session
        self.secret_key = app.config['JWT_SECRET_KEY']
        self.access_token_expires = app.config['JWT_ACCESS_TOKEN_EXPIRES']
        self.refresh_token_expires = app.config['JWT_REFRESH_TOKEN_EXPIRES']
    
    def generate_tokens(self, user):
        """Generate access and refresh tokens for user"""
        access_token = jwt.encode({
            'user_id': user.id,
            'email': user.email,
            'subscription_tier': user.subscription_tier,
            'exp': datetime.utcnow() + self.access_token_expires,
            'type': 'access'
        }, self.secret_key, algorithm='HS256')
        
        refresh_token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + self.refresh_token_expires,
            'type': 'refresh'
        }, self.secret_key, algorithm='HS256')
        
        return access_token, refresh_token
    
    def verify_token(self, token):
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def verify_api_key(self, api_key):
        """Verify API key and return associated user"""
        # Hash the provided key
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Look up in database
        api_key_obj = self.db.query(APIKey).filter_by(
            key_hash=key_hash,
            is_active=True
        ).first()
        
        if not api_key_obj:
            return None
        
        # Check expiration
        if api_key_obj.expires_at and api_key_obj.expires_at < datetime.utcnow():
            return None
        
        # Update usage
        api_key_obj.last_used = datetime.utcnow()
        api_key_obj.usage_count += 1
        self.db.commit()
        
        return api_key_obj.user
    
    def create_api_key(self, user, name, description=None, expires_in_days=None):
        """Create a new API key for user"""
        # Generate key
        raw_key = APIKey.generate_key()
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key_prefix = raw_key[:12]
        
        # Calculate expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        
        # Create API key object
        api_key = APIKey(
            user_id=user.id,
            key_hash=key_hash,
            key_prefix=key_prefix,
            name=name,
            description=description,
            expires_at=expires_at
        )
        
        self.db.add(api_key)
        self.db.commit()
        
        # Return the raw key (only time it's visible)
        return raw_key, api_key
    
    def get_current_user(self):
        """Get current authenticated user from request context"""
        # Check for JWT token in Authorization header
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            payload = self.verify_token(token)
            if payload and payload.get('type') == 'access':
                user = self.db.query(User).filter_by(id=payload['user_id']).first()
                if user and user.is_active:
                    return user
        
        # Check for API key in X-API-Key header
        api_key = request.headers.get('X-API-Key', '')
        if api_key:
            user = self.verify_api_key(api_key)
            if user and user.is_active:
                return user
        
        return None
    
    def log_auth_event(self, user_id, event_type, success=True, details=None):
        """Log authentication event to audit log"""
        log = AuditLog(
            user_id=user_id,
            event_type=event_type,
            event_category='auth',
            severity='info' if success else 'warning',
            description=f"Authentication event: {event_type}",
            details=details,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            endpoint=request.endpoint,
            method=request.method,
            success=success
        )
        self.db.add(log)
        self.db.commit()


def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import current_app
        
        auth_manager = current_app.auth_manager
        user = auth_manager.get_current_user()
        
        if not user:
            return jsonify({
                'error': 'Authentication required',
                'message': 'Please provide a valid JWT token or API key'
            }), 401
        
        # Store user in request context
        g.current_user = user
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_admin(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(g, 'current_user') or not g.current_user.is_admin:
            return jsonify({
                'error': 'Admin access required',
                'message': 'This endpoint requires administrator privileges'
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function


def check_rate_limit(user, tier_limits):
    """Check if user has exceeded rate limits"""
    from config import get_config
    config = get_config()
    
    tier = user.subscription_tier
    limits = config.SUBSCRIPTION_TIERS.get(tier, config.SUBSCRIPTION_TIERS['free'])
    
    # Reset daily counter if needed
    if user.last_scan_date and user.last_scan_date.date() < datetime.utcnow().date():
        user.scans_this_day = 0
    
    # Check daily limit
    daily_limit = limits['scans_per_day']
    if daily_limit > 0 and user.scans_this_day >= daily_limit:
        return False, f"Daily limit of {daily_limit} scans exceeded"
    
    # Check monthly limit
    monthly_limit = limits['scans_per_month']
    if monthly_limit > 0 and user.scans_this_month >= monthly_limit:
        return False, f"Monthly limit of {monthly_limit} scans exceeded"
    
    return True, None


def increment_scan_count(user, db_session):
    """Increment user's scan counters"""
    user.scans_this_day += 1
    user.scans_this_month += 1
    user.total_scans += 1
    user.last_scan_date = datetime.utcnow()
    db_session.commit()
