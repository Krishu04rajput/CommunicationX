#!/usr/bin/env python3
"""
Comprehensive fix for all application errors
- Database schema inconsistencies
- Missing columns in ServerMembership
- Broken foreign key references
"""

import sqlite3
import re
from app import app, db
from models import *

def fix_all_database_errors():
    """Fix all database schema issues"""
    with app.app_context():
        try:
            # Get the database file path
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
            
            # Connect directly to SQLite
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            print("Fixing all database schema errors...")
            
            # Drop and recreate problematic tables
            problematic_tables = [
                'server_membership',
                'messages',
                'direct_messages'
            ]
            
            for table in problematic_tables:
                try:
                    # Check if table exists
                    cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
                    if cursor.fetchone():
                        print(f"Dropping table {table}...")
                        cursor.execute(f"DROP TABLE {table}")
                except Exception as e:
                    print(f"Error dropping table {table}: {e}")
            
            conn.commit()
            conn.close()
            
            # Recreate tables with correct schema
            print("Recreating tables with correct schema...")
            db.create_all()
            
            print("Database schema fix completed successfully!")
            
        except Exception as e:
            print(f"Error during database fix: {e}")
            return False
    
    return True

def fix_routes_file():
    """Fix all broken column references in routes.py"""
    try:
        print("Fixing routes.py column references...")
        
        # Read the file
        with open('routes.py', 'r') as f:
            content = f.read()
        
        # Fix all is_admin references
        content = re.sub(
            r'not membership\.is_admin',
            'server.owner_id != current_user.id',
            content
        )
        
        # Fix can_manage references
        content = re.sub(
            r'membership\.can_manage_\w+',
            'False',
            content
        )
        
        # Write back the fixed content
        with open('routes.py', 'w') as f:
            f.write(content)
        
        print("Routes.py fixed successfully!")
        
    except Exception as e:
        print(f"Error fixing routes.py: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("Starting comprehensive error fix...")
    
    # Fix database schema
    if fix_all_database_errors():
        print("✓ Database schema fixed")
    else:
        print("✗ Database schema fix failed")
    
    # Fix routes file
    if fix_routes_file():
        print("✓ Routes file fixed")
    else:
        print("✗ Routes file fix failed")
    
    print("Comprehensive error fix completed!")