
import sqlite3
import os
from datetime import datetime

def fix_direct_messages_database():
    """Completely fix the direct_messages table structure"""
    db_path = 'communicationx.db'
    
    if not os.path.exists(db_path):
        print("Database file not found")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("Fixing direct_messages table...")
        
        # Check if table exists and get current data
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='direct_messages'")
        table_exists = cursor.fetchone()
        
        existing_data = []
        if table_exists:
            try:
                cursor.execute("SELECT content, sender_id, recipient_id, created_at, read_at, status, delivered_at FROM direct_messages")
                existing_data = cursor.fetchall()
                print(f"Found {len(existing_data)} existing messages to preserve")
            except sqlite3.OperationalError as e:
                print(f"Error reading existing data: {e}")
                # Try to get basic data
                try:
                    cursor.execute("SELECT content, sender_id, recipient_id FROM direct_messages")
                    basic_data = cursor.fetchall()
                    existing_data = [(content, sender_id, recipient_id, datetime.now().isoformat(), None, 'sent', None) 
                                   for content, sender_id, recipient_id in basic_data]
                    print(f"Retrieved {len(existing_data)} messages with basic data")
                except:
                    print("Could not retrieve any existing data")
        
        # Drop existing table
        cursor.execute("DROP TABLE IF EXISTS direct_messages")
        print("Dropped existing direct_messages table")
        
        # Create new table with proper structure
        cursor.execute("""
            CREATE TABLE direct_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                read_at TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'sent',
                delivered_at TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (recipient_id) REFERENCES users(id)
            )
        """)
        print("Created new direct_messages table with proper auto-increment")
        
        # Restore data if any existed
        if existing_data:
            cursor.executemany("""
                INSERT INTO direct_messages (content, sender_id, recipient_id, created_at, read_at, status, delivered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, existing_data)
            print(f"Restored {len(existing_data)} messages")
        
        # Create indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dm_conversation ON direct_messages(sender_id, recipient_id, created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dm_recipient_unread ON direct_messages(recipient_id, read_at, created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dm_user_timeline ON direct_messages(sender_id, created_at)")
        print("Created performance indexes")
        
        # Test the table structure
        cursor.execute("PRAGMA table_info(direct_messages)")
        columns = cursor.fetchall()
        print("\nNew table structure:")
        for col in columns:
            print(f"  {col}")
        
        # Test insert
        try:
            cursor.execute("""
                INSERT INTO direct_messages (content, sender_id, recipient_id, status)
                VALUES ('Test message', 'test_user', 'test_recipient', 'sent')
            """)
            test_id = cursor.lastrowid
            print(f"\nTest insert successful - got ID: {test_id}")
            
            # Clean up test
            cursor.execute("DELETE FROM direct_messages WHERE id = ?", (test_id,))
            print("Test message cleaned up")
            
        except Exception as e:
            print(f"Test insert failed: {e}")
            conn.rollback()
            return False
        
        conn.commit()
        print("\n✅ Direct messages table fixed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error fixing database: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    fix_direct_messages_database()
