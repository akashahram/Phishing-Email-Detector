# Database Connection and Session Management
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from contextlib import contextmanager
from models import Base


class Database:
    """Database connection manager"""
    
    def __init__(self, database_url):
        self.engine = create_engine(
            database_url,
            pool_pre_ping=True,  # Verify connections before using
            pool_recycle=3600,   # Recycle connections after 1 hour
            echo=False           # Set to True for SQL debugging
        )
        
        self.Session = scoped_session(sessionmaker(bind=self.engine))
    
    def create_all(self):
        """Create all tables"""
        Base.metadata.create_all(self.engine)
    
    def drop_all(self):
        """Drop all tables (use with caution!)"""
        Base.metadata.drop_all(self.engine)
    
    def get_session(self):
        """Get a new database session"""
        return self.Session()
    
    @contextmanager
    def session_scope(self):
        """Provide a transactional scope for database operations"""
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def close(self):
        """Close all sessions"""
        self.Session.remove()


def init_db(app):
    """Initialize database with Flask app"""
    database_url = app.config['DATABASE_URL']
    db = Database(database_url)
    
    # Create tables if they don't exist
    db.create_all()
    
    # Store in app context
    app.db = db
    
    # Setup teardown
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db.Session.remove()
    
    return db
