# Rate Limiting Module
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import g, request
from functools import wraps


def get_user_identifier():
    """Get identifier for rate limiting (user ID or IP)"""
    # If user is authenticated, use user ID
    if hasattr(g, 'current_user') and g.current_user:
        return f"user:{g.current_user.id}"
    
    # Otherwise use IP address
    return f"ip:{get_remote_address()}"


def get_rate_limit_for_user():
    """Get rate limit based on user's subscription tier"""
    if hasattr(g, 'current_user') and g.current_user:
        tier = g.current_user.subscription_tier
        
        # Rate limits per tier (requests per minute)
        limits = {
            'free': '10 per minute',
            'pro': '100 per minute',
            'enterprise': '1000 per minute'
        }
        
        return limits.get(tier, limits['free'])
    
    # Default for unauthenticated users
    return '5 per minute'


def init_limiter(app):
    """Initialize rate limiter"""
    limiter = Limiter(
        app=app,
        key_func=get_user_identifier,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=app.config.get('RATELIMIT_STORAGE_URL', 'memory://'),
        strategy='fixed-window'
    )
    
    return limiter


def custom_rate_limit(limit_string):
    """Custom rate limit decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # This will be handled by Flask-Limiter
            return f(*args, **kwargs)
        return decorated_function
    return decorator
