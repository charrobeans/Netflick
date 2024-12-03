import sqlite3

DATABASE = 'database.db'

conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

# Add the `image_path` column to the `videos` table
try:
    cursor.execute("ALTER TABLE videos ADD COLUMN image_path TEXT")
    print("Column 'image_path' added successfully.")
except sqlite3.OperationalError as e:
    print("Error:", e)
    print("The 'image_path' column may already exist.")

# Optionally, update "The Batman" and "Godzilla" with image paths if they already exist
video_images = [
    ("Godzilla", "static/videos/godzilla.mp4"),
    ("The Batman", "static/videos/batman.mp4")
]

for title, image_path in video_images:
    cursor.execute("UPDATE videos SET image_path = ? WHERE title = ?", (image_path, title))

conn.commit()
conn.close()
