import sqlite3

DATABASE = 'database.db'  # Make sure this matches your actual database file name

conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

# Add the `wishlist` column to the `users` table if it doesn't already exist
try:
    cursor.execute("ALTER TABLE users ADD COLUMN wishlist TEXT DEFAULT 'Godzilla,The Batman'")
    print("Column 'wishlist' added successfully.")
except sqlite3.OperationalError as e:
    print("Error:", e)
    print("The 'wishlist' column may already exist.")

conn.commit()
conn.close()
