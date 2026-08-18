#!/usr/bin/env python3
"""
Fix User ID schema inconsistency
The User model has Integer primary key but foreign keys reference it as String
This causes authentication and registration issues
"""

import sqlite3
from app import app, db
from models import *

def fix_user_id_schema():
    """Fix the user_id foreign key type mismatches"""
    with app.app_context():
        try:
            # Get the database file path
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
            
            # Connect directly to SQLite
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            print("Fixing User ID schema inconsistencies...")
            
            # Check current schema
            cursor.execute("PRAGMA table_info(users)")
            users_info = cursor.fetchall()
            print(f"Users table schema: {users_info}")
            
            # Tables that need user_id fixes
            tables_to_fix = [
                'server_membership',
                'messages', 
                'direct_messages',
                'message_reactions',
                'message_reports',
                'calls',
                'call_messages',
                'voicemails',
                'shared_files',
                'invitations',
                'audit_logs',
                'user_sessions',
                'user_activities'
            ]
            
            for table in tables_to_fix:
                try:
                    # Check if table exists
                    cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
                    if not cursor.fetchone():
                        print(f"Table {table} doesn't exist, skipping...")
                        continue
                    
                    # Get table info
                    cursor.execute(f"PRAGMA table_info({table})")
                    table_info = cursor.fetchall()
                    
                    # Check if user_id column exists and its type
                    user_id_col = None
                    for col in table_info:
                        if col[1] == 'user_id':
                            user_id_col = col
                            break
                    
                    if user_id_col and 'TEXT' in user_id_col[2].upper():
                        print(f"Fixing {table}.user_id from TEXT to INTEGER...")
                        
                        # Create backup table
                        cursor.execute(f"CREATE TABLE {table}_backup AS SELECT * FROM {table}")
                        
                        # Drop original table
                        cursor.execute(f"DROP TABLE {table}")
                        
                        # Let SQLAlchemy recreate with correct schema
                        print(f"Table {table} will be recreated with correct schema")
                        
                except Exception as e:
                    print(f"Error fixing table {table}: {e}")
                    continue
            
            conn.commit()
            conn.close()
            
            # Recreate tables with correct schema
            print("Recreating tables with correct schema...")
            db.create_all()
            
            print("Schema fix completed successfully!")
            
        except Exception as e:
            print(f"Error during schema fix: {e}")
            return False
    
    return True

if __name__ == "__main__":
    fix_user_id_schema()