# Applying the provided changes to fix database initialization and add migration functions.
import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
# Rate limiting removed for development
from urllib.parse import urlparse
import sqlite3
from sqlalchemy import inspect as sqlalchemy_inspect, text

# Configure logging with reduced verbosity for performance
logging.basicConfig(
    level=logging.WARNING,  # Reduced from INFO to WARNING
    format='%(levelname)s - %(message)s'  # Simplified format
)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Security configurations
app.config['WTF_CSRF_ENABLED'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# Database configuration.
# GitHub stores the source code; the application stores data in this database.
# Set DATABASE_URL for PostgreSQL in production. SQLite is the zero-config local default.
database_url = os.environ.get("DATABASE_URL", "").strip()
if database_url:
    # Normalize common postgres:// URLs for SQLAlchemy 2.x.
    if database_url.startswith("postgres://"):
        database_url = "postgresql://" + database_url[len("postgres://"):]
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///communicationx.db"
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {}

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# File upload configuration
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500MB max file size

# Rate limiting disabled for development
limiter = None

# Initialize extensions
db.init_app(app)
socketio = SocketIO(app, 
                   cors_allowed_origins="*", 
                   async_mode='threading',
                   logger=False, 
                   engineio_logger=False,
                   ping_timeout=60,
                   ping_interval=25,
                   allow_upgrades=True,
                   transports=['websocket', 'polling'])

def check_database_schema():
    """Check if database schema is up to date"""
    try:
        inspector = sqlalchemy_inspect(db.engine)
        table_names = inspector.get_table_names()

        # Check if server_membership table exists
        if 'server_membership' not in table_names:
            return False  # Table doesn't exist, need migration

        # Check for critical columns
        columns = {
            column['name']
            for column in inspector.get_columns('server_membership')
        }

        required_columns = ['custom_status', 'activity_status', 'boost_count', 'flags']
        missing = [col for col in required_columns if col not in columns]

        return len(missing) == 0
    except Exception as e:
        print(f"Schema check error: {e}")
        return False

def fix_direct_messages_table():
    """Fix DirectMessage table schema issues"""
    try:
        from sqlalchemy import text
        
        # First, check if we're using PostgreSQL or SQLite
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        is_postgres = 'postgresql' in db_uri or 'postgres' in db_uri
        
        if is_postgres:
            # For PostgreSQL, recreate the table with proper schema
            with db.engine.connect() as conn:
                # Drop and recreate the direct_messages table
                conn.execute(text('DROP TABLE IF EXISTS direct_messages CASCADE'))
                conn.execute(text('''
                    CREATE TABLE direct_messages (
                        id SERIAL PRIMARY KEY,
                        content TEXT NOT NULL,
                        sender_id INTEGER NOT NULL REFERENCES users(id),
                        recipient_id INTEGER NOT NULL REFERENCES users(id),
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        read_at TIMESTAMP,
                        status VARCHAR(20) NOT NULL DEFAULT 'sent',
                        delivered_at TIMESTAMP
                    )
                '''))
                
                # Create indexes
                conn.execute(text('CREATE INDEX idx_dm_conversation ON direct_messages (sender_id, recipient_id, created_at)'))
                conn.execute(text('CREATE INDEX idx_dm_recipient_unread ON direct_messages (recipient_id, read_at, created_at)'))
                conn.execute(text('CREATE INDEX idx_dm_user_timeline ON direct_messages (sender_id, created_at)'))
                
                conn.commit()
                print("DirectMessage table recreated with correct PostgreSQL schema")
        else:
            # SQLite fallback
            db_path = db_uri.replace('sqlite:///', '')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute('DROP TABLE IF EXISTS direct_messages')
            cursor.execute('''
                CREATE TABLE direct_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content TEXT NOT NULL,
                    sender_id INTEGER NOT NULL,
                    recipient_id INTEGER NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    read_at TIMESTAMP,
                    status VARCHAR(20) NOT NULL DEFAULT 'sent',
                    delivered_at TIMESTAMP,
                    FOREIGN KEY (sender_id) REFERENCES users (id),
                    FOREIGN KEY (recipient_id) REFERENCES users (id)
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX idx_dm_conversation ON direct_messages (sender_id, recipient_id, created_at)')
            cursor.execute('CREATE INDEX idx_dm_recipient_unread ON direct_messages (recipient_id, read_at, created_at)')
            cursor.execute('CREATE INDEX idx_dm_user_timeline ON direct_messages (sender_id, created_at)')
            
            conn.commit()
            conn.close()
            print("DirectMessage table recreated with correct SQLite schema")
            
    except Exception as e:
        print(f"Error fixing DirectMessage table: {e}")
        return False
    
    return True

def fix_shared_files_table():
    """Fix SharedFile table schema issues"""
    try:
        from sqlalchemy import text
        
        # First, check if we're using PostgreSQL or SQLite
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        is_postgres = 'postgresql' in db_uri or 'postgres' in db_uri
        
        if is_postgres:
            # For PostgreSQL, recreate the table with proper schema
            with db.engine.connect() as conn:
                # Drop and recreate the shared_files table
                conn.execute(text('DROP TABLE IF EXISTS shared_files CASCADE'))
                conn.execute(text('''
                    CREATE TABLE shared_files (
                        id SERIAL PRIMARY KEY,
                        filename VARCHAR(255) NOT NULL,
                        original_filename VARCHAR(255) NOT NULL,
                        file_data BYTEA,
                        file_path VARCHAR(500),
                        file_size BIGINT NOT NULL,
                        mime_type VARCHAR(100) NOT NULL,
                        uploader_id INTEGER NOT NULL REFERENCES users(id),
                        server_id INTEGER REFERENCES server(id),
                        channel_id INTEGER REFERENCES channel(id),
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        is_compressed BOOLEAN DEFAULT FALSE,
                        checksum VARCHAR(64)
                    )
                '''))
                
                # Create indexes
                conn.execute(text('CREATE INDEX idx_file_type_size ON shared_files (mime_type, file_size)'))
                conn.execute(text('CREATE INDEX idx_server_files ON shared_files (server_id, created_at)'))
                conn.execute(text('CREATE INDEX idx_channel_files ON shared_files (channel_id, created_at)'))
                conn.execute(text('CREATE INDEX idx_user_uploads ON shared_files (uploader_id, created_at)'))
                
                conn.commit()
                print("SharedFile table recreated with correct PostgreSQL schema")
        else:
            # For SQLite
            db_path = app.config.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///communicationx.db').replace('sqlite:///', '')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Drop existing table
            cursor.execute('DROP TABLE IF EXISTS shared_files')
            
            # Recreate table with correct schema
            cursor.execute('''
                CREATE TABLE shared_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename VARCHAR(255) NOT NULL,
                    original_filename VARCHAR(255) NOT NULL,
                    file_data BLOB,
                    file_path VARCHAR(500),
                    file_size BIGINT NOT NULL,
                    mime_type VARCHAR(100) NOT NULL,
                    uploader_id INTEGER NOT NULL REFERENCES users(id),
                    server_id INTEGER REFERENCES server(id),
                    channel_id INTEGER REFERENCES channel(id),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    is_compressed BOOLEAN DEFAULT 0,
                    checksum VARCHAR(64)
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX idx_file_type_size ON shared_files (mime_type, file_size)')
            cursor.execute('CREATE INDEX idx_server_files ON shared_files (server_id, created_at)')
            cursor.execute('CREATE INDEX idx_channel_files ON shared_files (channel_id, created_at)')
            cursor.execute('CREATE INDEX idx_user_uploads ON shared_files (uploader_id, created_at)')
            
            conn.commit()
            conn.close()
            print("SharedFile table recreated with correct SQLite schema")
            
    except Exception as e:
        print(f"Error fixing SharedFile table: {e}")
        return False
    
    return True

def run_migration():
    """Run database migration to add missing columns"""
    try:
        # Ensure all tables exist first
        db.create_all()

        # Always check and add missing columns regardless of table existence
        print("Running database migration to add missing columns...")

        migration_columns = {
            'server_membership': [
                ('custom_status', 'VARCHAR(128)'),
                ('activity_status', "VARCHAR(20) DEFAULT 'online'"),
                ('boost_count', 'INTEGER DEFAULT 0'),
                ('flags', 'INTEGER DEFAULT 0'),
                ('is_admin', 'BOOLEAN DEFAULT FALSE'),
                ('can_manage_server', 'BOOLEAN DEFAULT FALSE'),
                ('can_manage_channels', 'BOOLEAN DEFAULT FALSE'),
                ('can_kick_members', 'BOOLEAN DEFAULT FALSE'),
                ('can_ban_members', 'BOOLEAN DEFAULT FALSE'),
            ],
            'server': [
                ('password_hash', 'VARCHAR(256)'),
                ('password_enabled', 'BOOLEAN DEFAULT FALSE'),
                ('password_set_by', 'INTEGER'),
                ('password_set_at', 'DATETIME'),
                ('is_locked', 'BOOLEAN DEFAULT FALSE'),
                ('locked_by', 'INTEGER'),
                ('locked_at', 'DATETIME'),
                ('lock_reason', 'TEXT'),
            ],
            'users': [
                ('is_admin', 'BOOLEAN DEFAULT FALSE'),
                ('is_super_admin', 'BOOLEAN DEFAULT FALSE'),
                ('admin_permissions', 'TEXT'),
                ('is_banned', 'BOOLEAN DEFAULT FALSE'),
                ('ban_reason', 'TEXT'),
                ('banned_by', 'INTEGER'),
                ('banned_at', 'DATETIME'),
            ],
        }

        inspector = sqlalchemy_inspect(db.engine)
        existing_tables = set(inspector.get_table_names())
        for table_name, columns in migration_columns.items():
            if table_name not in existing_tables:
                continue

            existing_columns = {
                column['name']
                for column in inspector.get_columns(table_name)
            }
            for column_name, column_definition in columns:
                if column_name in existing_columns:
                    continue
                with db.engine.begin() as conn:
                    conn.execute(text(
                        f'ALTER TABLE "{table_name}" '
                        f'ADD COLUMN "{column_name}" {column_definition}'
                    ))
                print(f"Added column {column_name} to {table_name}")
                existing_columns.add(column_name)

        print("Migration completed successfully")
        return True

    except Exception as e:
        print(f"Migration failed: {e}")
        return False

def init_database():
    """Initialize database tables"""
    try:
        with app.app_context():
            # Always try to create tables first
            db.create_all()
            
            # Check if database needs migration for missing columns
            if not check_database_schema():
                print("Database schema outdated, running migration...")
                run_migration()
            else:
                print("Database already migrated.")

            print("Database tables initialized successfully")
            return True
    except Exception as e:
        print(f"Database initialization error: {e}")
        return False

# Import model definitions before initializing the database. Without this,
# SQLAlchemy's metadata is empty and create_all() silently creates no tables.
import models  # noqa: F401,E402

# Database initialization
#
# IMPORTANT:
# Do not initialize the database while Vercel is importing this module.
# Vercel imports the Flask app to create a serverless function, and
# connecting/migrating the database during import can crash the function.
#
# Database initialization should be performed separately when required.

def initialize_app_database():
    """Initialize the database explicitly when needed."""
    try:
        with app.app_context():
            return init_database()
    except Exception as e:
        app.logger.error(f"Database initialization failed: {e}")
        return False
