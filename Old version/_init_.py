import sqlite3

def create_database():
    # Connect to the SQLite database (creates it if it doesn't exist)
    conn = sqlite3.connect('app.db')
    
    # Create a cursor object to execute SQL commands
    cursor = conn.cursor()
    
    # Create the users table with the appropriate schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    
    # Create the notes table with the appropriate schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            password TEXT
        )
    ''')
    
    # Commit changes and close the connection
    conn.commit()
    conn.close()
    
    print("Database and tables created successfully.")

# Execute the function to create the database
if __name__ == "__main__":
    create_database()
