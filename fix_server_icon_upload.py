#!/usr/bin/env python3
"""
Fix server icon and banner upload functionality
This script handles the database schema migration and fixes upload issues
"""

import os
import sys
import sqlite3
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import Server

def fix_server_uploads():
    """Fix server icon and banner upload functionality"""
    
    with app.app_context():
        try:
            # Check if we're using SQLite
            database_url = os.environ.get('DATABASE_URL', 'sqlite:///communicationx.db')
            
            if 'sqlite' in database_url.lower():
                print("Using SQLite database - fixing schema...")
                
                # Connect directly to SQLite to handle schema changes
                db_path = database_url.replace('sqlite:///', '')
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Check if logo_url column exists and rename it to icon_url
                cursor.execute("PRAGMA table_info(server)")
                columns = [column[1] for column in cursor.fetchall()]
                
                if 'logo_url' in columns and 'icon_url' not in columns:
                    print("Renaming logo_url to icon_url...")
                    # SQLite doesn't support column rename directly, so we recreate the table
                    cursor.execute("""
                        CREATE TABLE server_new AS 
                        SELECT 
                            id, name, description, 
                            logo_url as icon_url, 
                            banner_url, owner_id, is_public,
                            verification_level, explicit_content_filter, default_notifications,
                            vanity_url, boost_level, boost_count, max_members, max_presences,
                            max_video_channel_users, afk_timeout, afk_channel_id, system_channel_id,
                            rules_channel_id, public_updates_channel_id, preferred_locale, features,
                            password_hash, password_enabled, password_set_by, password_set_at,
                            is_locked, locked_by, locked_at, lock_reason, created_at
                        FROM server
                    """)
                    
                    # Drop old table and rename new one
                    cursor.execute("DROP TABLE server")
                    cursor.execute("ALTER TABLE server_new RENAME TO server")
                    
                    print("Successfully renamed logo_url to icon_url")
                
                elif 'icon_url' in columns:
                    print("icon_url column already exists")
                else:
                    print("Adding icon_url column...")
                    cursor.execute("ALTER TABLE server ADD COLUMN icon_url TEXT")
                
                # Ensure banner_url column exists
                if 'banner_url' not in columns:
                    print("Adding banner_url column...")
                    cursor.execute("ALTER TABLE server ADD COLUMN banner_url TEXT")
                
                conn.commit()
                conn.close()
                
                print("Database schema updated successfully!")
                
            else:
                print("Using PostgreSQL - schema should be handled by SQLAlchemy migrations")
            
            # Recreate tables to ensure schema is current
            db.create_all()
            print("Database tables synchronized")
            
            return True
            
        except Exception as e:
            print(f"Error fixing server uploads: {e}")
            return False

if __name__ == "__main__":
    success = fix_server_uploads()
    if success:
        print("Server upload functionality fixed successfully!")
    else:
        print("Failed to fix server upload functionality")
        sys.exit(1)