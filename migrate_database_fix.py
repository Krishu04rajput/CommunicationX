
from app import app, db
from models import *
import sqlite3
import logging

def migrate_database():
    """Migrate database to add missing columns"""
    with app.app_context():
        try:
            # Get database path
            db_path = app.config.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///instance/communicationx.db').replace('sqlite:///', '')
            
            # Connect directly to SQLite
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Check if columns exist and add them if they don't
            cursor.execute("PRAGMA table_info(server_membership)")
            columns = [row[1] for row in cursor.fetchall()]
            
            missing_columns = []
            
            # Check for missing columns in ServerMembership
            expected_columns = [
                ('custom_status', 'VARCHAR(128)'),
                ('activity_status', 'VARCHAR(20) DEFAULT "online"'),
                ('boost_count', 'INTEGER DEFAULT 0'),
                ('flags', 'INTEGER DEFAULT 0')
            ]
            
            for col_name, col_type in expected_columns:
                if col_name not in columns:
                    missing_columns.append((col_name, col_type))
                    print(f"Adding missing column: {col_name}")
                    cursor.execute(f"ALTER TABLE server_membership ADD COLUMN {col_name} {col_type}")
            
            # Check Server table for password columns
            cursor.execute("PRAGMA table_info(server)")
            server_columns = [row[1] for row in cursor.fetchall()]
            
            server_missing_columns = [
                ('password_hash', 'VARCHAR(256)'),
                ('password_enabled', 'BOOLEAN DEFAULT FALSE'),
                ('password_set_by', 'INTEGER'),
                ('password_set_at', 'DATETIME'),
                ('is_locked', 'BOOLEAN DEFAULT FALSE'),
                ('locked_by', 'INTEGER'),
                ('locked_at', 'DATETIME'),
                ('lock_reason', 'TEXT')
            ]
            
            for col_name, col_type in server_missing_columns:
                if col_name not in server_columns:
                    print(f"Adding missing server column: {col_name}")
                    cursor.execute(f"ALTER TABLE server ADD COLUMN {col_name} {col_type}")
            
            # Check User table for admin columns
            cursor.execute("PRAGMA table_info(users)")
            user_columns = [row[1] for row in cursor.fetchall()]
            
            user_missing_columns = [
                ('is_admin', 'BOOLEAN DEFAULT FALSE'),
                ('is_super_admin', 'BOOLEAN DEFAULT FALSE'),
                ('admin_permissions', 'TEXT'),
                ('is_banned', 'BOOLEAN DEFAULT FALSE'),
                ('ban_reason', 'TEXT'),
                ('banned_by', 'INTEGER'),
                ('banned_at', 'DATETIME')
            ]
            
            for col_name, col_type in user_missing_columns:
                if col_name not in user_columns:
                    print(f"Adding missing user column: {col_name}")
                    cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
            
            conn.commit()
            conn.close()
            
            print("Database migration completed successfully!")
            return True
            
        except Exception as e:
            print(f"Migration error: {e}")
            if 'conn' in locals():
                conn.rollback()
                conn.close()
            return False

if __name__ == "__main__":
    migrate_database()
