# Audit Logging Module
from models import AuditLog
from flask import request, g
from datetime import datetime
import json


class AuditLogger:
    """Centralized audit logging"""
    
    def __init__(self, db_session):
        self.db = db_session
    
    def log(self, event_type, event_category='general', severity='info', 
            description=None, details=None, user_id=None, success=True):
        """Log an audit event"""
        
        # Get user ID from context if not provided
        if user_id is None and hasattr(g, 'current_user') and g.current_user:
            user_id = g.current_user.id
        
        # Create audit log entry
        log_entry = AuditLog(
            user_id=user_id,
            event_type=event_type,
            event_category=event_category,
            severity=severity,
            description=description,
            details=details,
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None,
            endpoint=request.endpoint if request else None,
            method=request.method if request else None,
            success=success
        )
        
        self.db.add(log_entry)
        self.db.commit()
        
        return log_entry
    
    def log_auth(self, event_type, user_id=None, success=True, details=None):
        """Log authentication event"""
        return self.log(
            event_type=event_type,
            event_category='auth',
            severity='info' if success else 'warning',
            description=f"Authentication: {event_type}",
            details=details,
            user_id=user_id,
            success=success
        )
    
    def log_scan(self, scan_type, result, user_id=None, details=None):
        """Log scan event"""
        return self.log(
            event_type=f'scan_{scan_type}',
            event_category='scan',
            severity='info',
            description=f"Scan performed: {scan_type}",
            details={
                'scan_type': scan_type,
                'result': result,
                **(details or {})
            },
            user_id=user_id,
            success=True
        )
    
    def log_api_access(self, endpoint, user_id=None, success=True, details=None):
        """Log API access"""
        return self.log(
            event_type='api_access',
            event_category='api',
            severity='info',
            description=f"API access: {endpoint}",
            details=details,
            user_id=user_id,
            success=success
        )
    
    def log_admin_action(self, action, user_id=None, details=None):
        """Log admin action"""
        return self.log(
            event_type=f'admin_{action}',
            event_category='admin',
            severity='warning',
            description=f"Admin action: {action}",
            details=details,
            user_id=user_id,
            success=True
        )
    
    def log_security_event(self, event_type, severity='warning', details=None):
        """Log security event"""
        return self.log(
            event_type=event_type,
            event_category='security',
            severity=severity,
            description=f"Security event: {event_type}",
            details=details,
            success=False
        )
    
    def get_user_audit_trail(self, user_id, limit=100):
        """Get audit trail for a specific user"""
        return self.db.query(AuditLog).filter_by(
            user_id=user_id
        ).order_by(
            AuditLog.created_at.desc()
        ).limit(limit).all()
    
    def get_recent_events(self, event_category=None, limit=100):
        """Get recent audit events"""
        query = self.db.query(AuditLog)
        
        if event_category:
            query = query.filter_by(event_category=event_category)
        
        return query.order_by(
            AuditLog.created_at.desc()
        ).limit(limit).all()
    
    def get_security_events(self, hours=24, limit=100):
        """Get recent security events"""
        from datetime import timedelta
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        return self.db.query(AuditLog).filter(
            AuditLog.event_category == 'security',
            AuditLog.created_at >= cutoff
        ).order_by(
            AuditLog.created_at.desc()
        ).limit(limit).all()
