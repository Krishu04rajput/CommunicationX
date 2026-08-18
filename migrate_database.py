
#!/usr/bin/env python3
"""
Database migration script to add missing columns to existing tables
"""

import sqlite3
import os
from datetime import datetime

DATABASE_PATH = 'instance/communicationx.db'

def migrate_database():
    """Add missing columns to existing tables"""
    if not os.path.exists(DATABASE_PATH):
        print("Database doesn't exist yet. No migration needed.")
        return
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    try:
        # Check if migration is needed by checking for custom_status column
        cursor.execute("PRAGMA table_info(server_membership)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'custom_status' in columns:
            print("Database already migrated.")
            conn.close()
            return
        
        print("Migrating database schema...")
        
        # Add missing columns to server_membership table
        migration_queries = [
            "ALTER TABLE server_membership ADD COLUMN custom_status VARCHAR(128)",
            "ALTER TABLE server_membership ADD COLUMN activity_status VARCHAR(20) DEFAULT 'online'",
            "ALTER TABLE server_membership ADD COLUMN boost_count INTEGER DEFAULT 0",
            "ALTER TABLE server_membership ADD COLUMN flags INTEGER DEFAULT 0",
        ]
        
        for query in migration_queries:
            try:
                cursor.execute(query)
                print(f"Executed: {query}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    print(f"Column already exists, skipping: {query}")
                else:
                    print(f"Error executing {query}: {e}")
        
        # Add missing columns to users table if needed
        cursor.execute("PRAGMA table_info(users)")
        user_columns = [column[1] for column in cursor.fetchall()]
        
        user_migration_queries = []
        if 'custom_status' not in user_columns:
            user_migration_queries.extend([
                "ALTER TABLE users ADD COLUMN custom_status VARCHAR(128)",
                "ALTER TABLE users ADD COLUMN banner_url VARCHAR",
                "ALTER TABLE users ADD COLUMN accent_color VARCHAR(7)",
                "ALTER TABLE users ADD COLUMN is_bot BOOLEAN DEFAULT 0",
                "ALTER TABLE users ADD COLUMN bot_token VARCHAR",
                "ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN DEFAULT 0",
                "ALTER TABLE users ADD COLUMN phone_number VARCHAR(20)",
                "ALTER TABLE users ADD COLUMN last_seen DATETIME DEFAULT CURRENT_TIMESTAMP",
                "ALTER TABLE users ADD COLUMN is_banned BOOLEAN DEFAULT 0",
                "ALTER TABLE users ADD COLUMN ban_reason TEXT",
                "ALTER TABLE users ADD COLUMN banned_by INTEGER",
                "ALTER TABLE users ADD COLUMN banned_at DATETIME",
                "ALTER TABLE users ADD COLUMN admin_permissions TEXT",
            ])
        
        for query in user_migration_queries:
            try:
                cursor.execute(query)
                print(f"Executed: {query}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    print(f"Column already exists, skipping: {query}")
                else:
                    print(f"Error executing {query}: {e}")
        
        # Add missing columns to servers table if needed
        cursor.execute("PRAGMA table_info(server)")
        server_columns = [column[1] for column in cursor.fetchall()]
        
        server_migration_queries = []
        if 'banner_url' not in server_columns:
            server_migration_queries.extend([
                "ALTER TABLE server ADD COLUMN banner_url VARCHAR",
                "ALTER TABLE server ADD COLUMN verification_level INTEGER DEFAULT 0",
                "ALTER TABLE server ADD COLUMN explicit_content_filter INTEGER DEFAULT 0",
                "ALTER TABLE server ADD COLUMN default_notifications VARCHAR(20) DEFAULT 'all'",
                "ALTER TABLE server ADD COLUMN vanity_url VARCHAR(50)",
                "ALTER TABLE server ADD COLUMN boost_level INTEGER DEFAULT 0",
                "ALTER TABLE server ADD COLUMN boost_count INTEGER DEFAULT 0",
                "ALTER TABLE server ADD COLUMN max_members INTEGER DEFAULT 500000",
                "ALTER TABLE server ADD COLUMN max_presences INTEGER DEFAULT 25000",
                "ALTER TABLE server ADD COLUMN max_video_channel_users INTEGER DEFAULT 25",
                "ALTER TABLE server ADD COLUMN afk_timeout INTEGER DEFAULT 300",
                "ALTER TABLE server ADD COLUMN afk_channel_id INTEGER",
                "ALTER TABLE server ADD COLUMN system_channel_id INTEGER",
                "ALTER TABLE server ADD COLUMN rules_channel_id INTEGER",
                "ALTER TABLE server ADD COLUMN public_updates_channel_id INTEGER",
                "ALTER TABLE server ADD COLUMN preferred_locale VARCHAR(10) DEFAULT 'en-US'",
                "ALTER TABLE server ADD COLUMN features TEXT",
                "ALTER TABLE server ADD COLUMN password_hash VARCHAR(256)",
                "ALTER TABLE server ADD COLUMN password_enabled BOOLEAN DEFAULT 0",
                "ALTER TABLE server ADD COLUMN password_set_by INTEGER",
                "ALTER TABLE server ADD COLUMN password_set_at DATETIME",
                "ALTER TABLE server ADD COLUMN is_locked BOOLEAN DEFAULT 0",
                "ALTER TABLE server ADD COLUMN locked_by INTEGER",
                "ALTER TABLE server ADD COLUMN locked_at DATETIME",
                "ALTER TABLE server ADD COLUMN lock_reason TEXT",
            ])
        
        for query in server_migration_queries:
            try:
                cursor.execute(query)
                print(f"Executed: {query}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    print(f"Column already exists, skipping: {query}")
                else:
                    print(f"Error executing {query}: {e}")
        
        # Add missing columns to channels table if needed
        cursor.execute("PRAGMA table_info(channel)")
        channel_columns = [column[1] for column in cursor.fetchall()]
        
        channel_migration_queries = []
        if 'channel_type' not in channel_columns:
            channel_migration_queries.extend([
                "ALTER TABLE channel ADD COLUMN channel_type VARCHAR(20) DEFAULT 'text'",
                "ALTER TABLE channel ADD COLUMN topic VARCHAR(1024)",
                "ALTER TABLE channel ADD COLUMN position INTEGER DEFAULT 0",
                "ALTER TABLE channel ADD COLUMN parent_id INTEGER",
                "ALTER TABLE channel ADD COLUMN bitrate INTEGER",
                "ALTER TABLE channel ADD COLUMN user_limit INTEGER",
                "ALTER TABLE channel ADD COLUMN rate_limit_per_user INTEGER DEFAULT 0",
                "ALTER TABLE channel ADD COLUMN nsfw BOOLEAN DEFAULT 0",
                "ALTER TABLE channel ADD COLUMN rtc_region VARCHAR(20)",
                "ALTER TABLE channel ADD COLUMN video_quality_mode INTEGER DEFAULT 1",
                "ALTER TABLE channel ADD COLUMN default_auto_archive_duration INTEGER DEFAULT 4320",
                "ALTER TABLE channel ADD COLUMN permissions_overwrites TEXT",
            ])
        
        for query in channel_migration_queries:
            try:
                cursor.execute(query)
                print(f"Executed: {query}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    print(f"Column already exists, skipping: {query}")
                else:
                    print(f"Error executing {query}: {e}")
        
        # Add missing columns to messages table if needed
        cursor.execute("PRAGMA table_info(messages)")
        message_columns = [column[1] for column in cursor.fetchall()]
        
        message_migration_queries = []
        if 'status' not in message_columns:
            message_migration_queries.extend([
                "ALTER TABLE messages ADD COLUMN status VARCHAR(20) DEFAULT 'sent'",
                "ALTER TABLE messages ADD COLUMN delivered_at DATETIME",
                "ALTER TABLE messages ADD COLUMN read_at DATETIME",
                "ALTER TABLE messages ADD COLUMN edited_at DATETIME",
                "ALTER TABLE messages ADD COLUMN is_pinned BOOLEAN DEFAULT 0",
                "ALTER TABLE messages ADD COLUMN reply_to_id BIGINT",
                "ALTER TABLE messages ADD COLUMN audio_url VARCHAR",
                "ALTER TABLE messages ADD COLUMN file_data BLOB",
            ])
        
        for query in message_migration_queries:
            try:
                cursor.execute(query)
                print(f"Executed: {query}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    print(f"Column already exists, skipping: {query}")
                else:
                    print(f"Error executing {query}: {e}")
        
        # Add missing columns to direct_messages table if needed
        cursor.execute("PRAGMA table_info(direct_messages)")
        dm_columns = [column[1] for column in cursor.fetchall()]
        
        dm_migration_queries = []
        if 'status' not in dm_columns:
            dm_migration_queries.extend([
                "ALTER TABLE direct_messages ADD COLUMN status VARCHAR(20) DEFAULT 'sent'",
                "ALTER TABLE direct_messages ADD COLUMN delivered_at DATETIME",
            ])
        
        for query in dm_migration_queries:
            try:
                cursor.execute(query)
                print(f"Executed: {query}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    print(f"Column already exists, skipping: {query}")
                else:
                    print(f"Error executing {query}: {e}")
        
        conn.commit()
        print("Database migration completed successfully!")
        
    except Exception as e:
        print(f"Migration failed: {e}")
        conn.rollback()
    
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database()
