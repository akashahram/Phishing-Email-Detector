# Database Models for Shadow Ops
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

Base = declarative_base()


class User(Base):
    """User account model"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255))
    company = Column(String(255))
    
    # Subscription
    subscription_tier = Column(String(50), default='free', nullable=False)
    subscription_status = Column(String(50), default='active')  # active, cancelled, expired
    subscription_start = Column(DateTime, default=datetime.utcnow)
    subscription_end = Column(DateTime)
    
    # Usage tracking
    scans_this_month = Column(Integer, default=0)
    scans_this_day = Column(Integer, default=0)
    last_scan_date = Column(DateTime)
    total_scans = Column(Integer, default=0)
    
    # Account status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relationships
    api_keys = relationship('APIKey', back_populates='user', cascade='all, delete-orphan')
    scan_history = relationship('ScanHistory', back_populates='user', cascade='all, delete-orphan')
    audit_logs = relationship('AuditLog', back_populates='user', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'full_name': self.full_name,
            'company': self.company,
            'subscription_tier': self.subscription_tier,
            'subscription_status': self.subscription_status,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'total_scans': self.total_scans
        }


class APIKey(Base):
    """API Key model for programmatic access"""
    __tablename__ = 'api_keys'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Key details
    key_hash = Column(String(255), unique=True, nullable=False, index=True)
    key_prefix = Column(String(20), nullable=False)  # First few chars for identification
    name = Column(String(100))
    description = Column(Text)
    
    # Usage tracking
    last_used = Column(DateTime)
    usage_count = Column(Integer, default=0)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime)
    
    # Relationships
    user = relationship('User', back_populates='api_keys')
    
    @staticmethod
    def generate_key():
        """Generate a new API key"""
        return f"sk_{''.join(secrets.token_urlsafe(32))}"
    
    def to_dict(self, include_key=False):
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'name': self.name,
            'key_prefix': self.key_prefix,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'usage_count': self.usage_count
        }
        return data


class ScanHistory(Base):
    """Scan history model"""
    __tablename__ = 'scan_history'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Scan details
    scan_type = Column(String(50), nullable=False)  # 'text' or 'eml'
    content_hash = Column(String(64), index=True)  # SHA256 hash for deduplication
    
    # Results
    prediction = Column(Integer, nullable=False)  # 0 = safe, 1 = phishing
    probability = Column(Float, nullable=False)
    ml_score = Column(Float)
    url_risk_score = Column(Integer)
    forensics_score = Column(Integer)
    reason = Column(Text)
    
    # Detailed findings (stored as JSON)
    findings = Column(JSON)
    
    # Metadata
    ip_address = Column(String(45))
    user_agent = Column(String(255))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    user = relationship('User', back_populates='scan_history')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'scan_type': self.scan_type,
            'prediction': self.prediction,
            'probability': self.probability,
            'ml_score': self.ml_score,
            'url_risk_score': self.url_risk_score,
            'forensics_score': self.forensics_score,
            'reason': self.reason,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AuditLog(Base):
    """Audit log model for security and compliance"""
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    
    # Event details
    event_type = Column(String(50), nullable=False, index=True)  # login, logout, scan, api_key_created, etc.
    event_category = Column(String(50), nullable=False)  # auth, scan, admin, etc.
    severity = Column(String(20), default='info')  # info, warning, error, critical
    
    # Event data
    description = Column(Text)
    details = Column(JSON)  # Additional structured data
    
    # Request metadata
    ip_address = Column(String(45))
    user_agent = Column(String(255))
    endpoint = Column(String(255))
    method = Column(String(10))
    
    # Status
    status_code = Column(Integer)
    success = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    user = relationship('User', back_populates='audit_logs')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'event_type': self.event_type,
            'event_category': self.event_category,
            'severity': self.severity,
            'description': self.description,
            'ip_address': self.ip_address,
            'success': self.success,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Webhook(Base):
    """Webhook configuration model"""
    __tablename__ = 'webhooks'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Webhook details
    url = Column(String(500), nullable=False)
    secret = Column(String(255))  # For signature verification
    events = Column(JSON)  # List of events to subscribe to
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Delivery tracking
    last_delivery = Column(DateTime)
    last_delivery_status = Column(Integer)
    failure_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'url': self.url,
            'events': self.events,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
