
import sqlite3
import os

def fix_direct_messages_table():
    """Fix the direct_messages table to have proper auto-increment ID"""
    db_path = 'communicationx.db'
    
    if not os.path.exists(db_path):
        print("Database file not found")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='direct_messages'")
        if not cursor.fetchone():
            print("direct_messages table doesn't exist yet")
            conn.close()
            return
        
        # Get current table structure
        cursor.execute("PRAGMA table_info(direct_messages)")
        columns = cursor.fetchall()
        
        print("Current table structure:")
        for col in columns:
            print(f"  {col}")
        
        # Check if we need to recreate the table
        id_column = next((col for col in columns if col[1] == 'id'), None)
        if id_column and id_column[5] == 1:  # pk = 1 means it's already primary key
            print("Table structure looks correct")
            conn.close()
            return
        
        print("Fixing direct_messages table...")
        
        # Backup existing data
        cursor.execute("SELECT * FROM direct_messages")
        existing_data = cursor.fetchall()
        
        # Drop and recreate table with correct structure
        cursor.execute("DROP TABLE IF EXISTS direct_messages_backup")
        cursor.execute("""
            CREATE TABLE direct_messages_backup AS 
            SELECT content, sender_id, recipient_id, created_at, read_at, status, delivered_at 
            FROM direct_messages
        """)
        
        # Drop original table
        cursor.execute("DROP TABLE direct_messages")
        
        # Create new table with proper structure
        cursor.execute("""
            CREATE TABLE direct_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                read_at DATETIME,
                status TEXT NOT NULL DEFAULT 'sent',
                delivered_at DATETIME,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (recipient_id) REFERENCES users(id)
            )
        """)
        
        # Restore data
        cursor.execute("""
            INSERT INTO direct_messages (content, sender_id, recipient_id, created_at, read_at, status, delivered_at)
            SELECT content, sender_id, recipient_id, created_at, read_at, status, delivered_at
            FROM direct_messages_backup
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX idx_dm_conversation ON direct_messages(sender_id, recipient_id, created_at)")
        cursor.execute("CREATE INDEX idx_dm_recipient_unread ON direct_messages(recipient_id, read_at, created_at)")
        cursor.execute("CREATE INDEX idx_dm_user_timeline ON direct_messages(sender_id, created_at)")
        
        # Clean up backup table
        cursor.execute("DROP TABLE direct_messages_backup")
        
        conn.commit()
        print("Successfully fixed direct_messages table!")
        
    except Exception as e:
        print(f"Error fixing table: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    fix_direct_messages_table()
