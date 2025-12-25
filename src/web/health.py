# Health Check and Status Endpoints
from flask import jsonify, current_app
from datetime import datetime
import psutil
import os


def register_health_endpoints(app):
    """Register health check and status endpoints"""
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """Basic health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '2.0.0'
        }), 200
    
    @app.route('/health/detailed', methods=['GET'])
    def detailed_health():
        """Detailed health check with system metrics"""
        try:
            # Database check
            db_healthy = check_database_health(app)
            
            # Redis check
            redis_healthy = check_redis_health(app)
            
            # System metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            health_status = {
                'status': 'healthy' if (db_healthy and redis_healthy) else 'degraded',
                'timestamp': datetime.utcnow().isoformat(),
                'version': '2.0.0',
                'components': {
                    'database': 'healthy' if db_healthy else 'unhealthy',
                    'redis': 'healthy' if redis_healthy else 'unhealthy',
                    'ml_model': 'healthy'  # Assume healthy if app started
                },
                'system': {
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'disk_percent': disk.percent
                }
            }
            
            status_code = 200 if health_status['status'] == 'healthy' else 503
            return jsonify(health_status), status_code
            
        except Exception as e:
            return jsonify({
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }), 503
    
    @app.route('/status', methods=['GET'])
    def status():
        """Application status and statistics"""
        try:
            from models import User, ScanHistory
            
            db_session = app.db.get_session()
            
            # Get statistics
            total_users = db_session.query(User).count()
            active_users = db_session.query(User).filter_by(is_active=True).count()
            total_scans = db_session.query(ScanHistory).count()
            
            # Get recent scan count (last 24 hours)
            from datetime import timedelta
            cutoff = datetime.utcnow() - timedelta(hours=24)
            recent_scans = db_session.query(ScanHistory).filter(
                ScanHistory.created_at >= cutoff
            ).count()
            
            return jsonify({
                'status': 'operational',
                'timestamp': datetime.utcnow().isoformat(),
                'version': '2.0.0',
                'statistics': {
                    'total_users': total_users,
                    'active_users': active_users,
                    'total_scans': total_scans,
                    'scans_24h': recent_scans
                },
                'uptime_seconds': get_uptime()
            }), 200
            
        except Exception as e:
            return jsonify({
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }), 500


def check_database_health(app):
    """Check if database is accessible"""
    try:
        db_session = app.db.get_session()
        db_session.execute('SELECT 1')
        return True
    except Exception:
        return False


def check_redis_health(app):
    """Check if Redis is accessible"""
    try:
        import redis
        redis_url = app.config.get('REDIS_URL')
        if redis_url:
            r = redis.from_url(redis_url)
            r.ping()
            return True
        return True  # Redis is optional
    except Exception:
        return False


# Track application start time
_start_time = datetime.utcnow()

def get_uptime():
    """Get application uptime in seconds"""
    return (datetime.utcnow() - _start_time).total_seconds()
