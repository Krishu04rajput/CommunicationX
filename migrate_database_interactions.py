#!/usr/bin/env python3
"""
Database migration script to create tables with message interaction features
"""
import sqlite3
import os
from datetime import datetime

def create_database():
    """Create database with message interaction support"""
    db_path = 'communicationx.db'
    
    # Remove existing database
    if os.path.exists(db_path):
        os.remove(db_path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create users table with all required columns
    cursor.execute('''
        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE,
            first_name TEXT,
            last_name TEXT,
            profile_image_url TEXT,
            username TEXT,
            password_hash TEXT,
            bio TEXT,
            status TEXT DEFAULT 'online',
            location TEXT,
            custom_status TEXT,
            banner_url TEXT,
            accent_color TEXT,
            is_bot BOOLEAN DEFAULT 0,
            bot_token TEXT,
            two_factor_enabled BOOLEAN DEFAULT 0,
            phone_number TEXT,
            email_verified BOOLEAN DEFAULT 0,
            last_seen TIMESTAMP,
            is_admin BOOLEAN DEFAULT 0,
            is_super_admin BOOLEAN DEFAULT 0,
            admin_permissions TEXT,
            is_banned BOOLEAN DEFAULT 0,
            ban_reason TEXT,
            banned_by TEXT,
            banned_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create servers table
    cursor.execute('''
        CREATE TABLE server (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            owner_id TEXT NOT NULL,
            icon_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    ''')
    
    # Create channels table
    cursor.execute('''
        CREATE TABLE channel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            server_id INTEGER NOT NULL,
            channel_type TEXT DEFAULT 'text',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (server_id) REFERENCES server(id)
        )
    ''')
    
    # Create server_membership table with all required columns
    cursor.execute('''
        CREATE TABLE server_membership (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            server_id INTEGER NOT NULL,
            nickname TEXT,
            avatar_url TEXT,
            roles TEXT,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            premium_since TIMESTAMP,
            deaf BOOLEAN DEFAULT 0,
            mute BOOLEAN DEFAULT 0,
            pending BOOLEAN DEFAULT 0,
            communication_disabled_until TIMESTAMP,
            custom_status TEXT,
            activity_status TEXT DEFAULT 'online',
            boost_count INTEGER DEFAULT 0,
            flags INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (server_id) REFERENCES server(id)
        )
    ''')
    
    # Create messages table with interaction features
    cursor.execute('''
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            author_id TEXT NOT NULL,
            channel_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            edited_at TIMESTAMP,
            is_pinned BOOLEAN DEFAULT 0,
            reply_to_id INTEGER,
            message_type TEXT DEFAULT 'text',
            audio_url TEXT,
            file_data BLOB,
            status TEXT DEFAULT 'sending',
            delivered_at TIMESTAMP,
            read_at TIMESTAMP,
            deleted_at TIMESTAMP,
            forwarded_from_id INTEGER,
            reaction_count INTEGER DEFAULT 0,
            reply_count INTEGER DEFAULT 0,
            FOREIGN KEY (author_id) REFERENCES users(id),
            FOREIGN KEY (channel_id) REFERENCES channel(id)
        )
    ''')
    
    # Create message_reactions table
    cursor.execute('''
        CREATE TABLE message_reaction (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            user_id TEXT NOT NULL,
            emoji TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (message_id) REFERENCES messages(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(message_id, user_id, emoji)
        )
    ''')
    
    # Create direct_messages table
    cursor.execute('''
        CREATE TABLE direct_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            read BOOLEAN DEFAULT 0,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        )
    ''')
    
    # Create calls table
    cursor.execute('''
        CREATE TABLE call (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            caller_id TEXT NOT NULL,
            receiver_id TEXT,
            channel_id INTEGER,
            call_type TEXT DEFAULT 'voice',
            status TEXT DEFAULT 'ringing',
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ended_at TIMESTAMP,
            FOREIGN KEY (caller_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id),
            FOREIGN KEY (channel_id) REFERENCES channel(id)
        )
    ''')
    
    # Create other necessary tables
    cursor.execute('''
        CREATE TABLE oauth (
            provider TEXT NOT NULL,
            user_id TEXT,
            browser_session_key TEXT NOT NULL,
            token TEXT,
            PRIMARY KEY (provider, browser_session_key),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Create indexes for performance
    cursor.execute('CREATE INDEX idx_messages_channel_created ON messages(channel_id, created_at)')
    cursor.execute('CREATE INDEX idx_messages_author_created ON messages(author_id, created_at)')
    cursor.execute('CREATE INDEX idx_server_membership_user_server ON server_membership(user_id, server_id)')
    cursor.execute('CREATE INDEX idx_message_reactions_message ON message_reaction(message_id)')
    
    conn.commit()
    
    # Insert default user for testing
    cursor.execute('''
        INSERT INTO users (id, email, first_name, last_name) 
        VALUES ('1', 'k.rajput0542@gmail.com', 'Test', 'User')
    ''')
    
    # Insert default server
    cursor.execute('''
        INSERT INTO server (id, name, description, owner_id) 
        VALUES (1, 'General Server', 'Default communication server', '1')
    ''')
    
    # Insert default channel
    cursor.execute('''
        INSERT INTO channel (id, name, description, server_id, channel_type) 
        VALUES (1, 'general', 'General discussion channel', 1, 'text')
    ''')
    
    # Insert server membership
    cursor.execute('''
        INSERT INTO server_membership (user_id, server_id) 
        VALUES ('1', 1)
    ''')
    
    conn.commit()
    conn.close()
    
    print("Database created successfully with message interaction features!")

if __name__ == "__main__":
    create_database()