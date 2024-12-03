import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
from datetime import datetime, timedelta
import re

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DATABASE = 'database.db'

# Logger Configuration
logging.basicConfig(
    filename='security.log',
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database Initialization
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            wishlist TEXT DEFAULT 'Godzilla,The Batman'
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            file_path TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            username TEXT NOT NULL,
            attempts INTEGER DEFAULT 0,
            last_attempt DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()

def add_videos():
    video_data = [
        ("Godzilla", "Big lizard wrecks havoc.", "videos/godzilla.mp4"),
        ("La La Land", "Emma stone heart eyes.", "videos/lalaland.mp4"),
        ("Star Wars: The Force Awakens", "Downfall of star wars.", "videos/starwars7.mp4"),
        ("The Batman", "Guy in a bat suit.", "videos/batman.mp4"),
        ("Whiplash", "Drummer jazz stuff.", "videos/whiplash.mp4")
    ]

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    for title, description, file_path in video_data:
        cursor.execute("""
            INSERT OR IGNORE INTO videos (title, description, file_path) VALUES (?, ?, ?)
        """, (title, description, file_path))
    conn.commit()
    conn.close()

def validate_password(password):
    # Check if password is at least 8 characters long
    if len(password) < 8:
        return 'Password must be at least 8 characters long.'
    
    # Check if password contains at least one digit
    if not re.search(r'\d', password):
        return 'Password must contain at least one number.'
    
    # Check if password contains at least one letter
    if not re.search(r'[A-Za-z]', password):
        return 'Password must contain at least one letter.'
    
    # Check if password contains at least one special character
    if not re.search(r'[\W_]', password):  # \W matches non-alphanumeric characters
        return 'Password must contain at least one special character.'
    
    return None  # No errors

# Sanitize input function
def sanitize_input(input_data):
    return input_data.strip()

# Username validation
def validate_username(username):
    # Check that the username is alphanumeric and between 3-20 characters
    return re.match(r'^[A-Za-z0-9]{3,20}$', username) is not None

# Email validation
def validate_email(email):
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None
# Verify password function
def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Log Configuration
logging.basicConfig(
    filename='security.log',  # Malicious/error-specific log file
    level=logging.WARNING,  # Only logs WARNING, ERROR, or CRITICAL messages
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Log Filter
class MaliciousActivityFilter(logging.Filter):
    def filter(self, record):
        return "MALICIOUS" in record.msg or record.levelname in ["ERROR", "CRITICAL"]

# Create a logger
logger = logging.getLogger('malicious_logger')
logger.setLevel(logging.DEBUG)  # Set the base level for the logger

# Create a file handler to save logs to a file
file_handler = logging.FileHandler('malicious_activity.log')
file_handler.setLevel(logging.DEBUG)  # Set the base level for the handler

# Add the filter to the handler
filter = MaliciousActivityFilter()
file_handler.addFilter(filter)

# Add the handler to the logger
logger.addHandler(file_handler)

# Route: Home
@app.route('/')
def home():
    return render_template('home.html')

# Route: Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = sanitize_input(request.form['first_name'])
        last_name = sanitize_input(request.form['last_name'])
        username = sanitize_input(request.form['username'])
        email = sanitize_input(request.form['email'])
        password = request.form['password']

        if not first_name.isalpha() or not last_name.isalpha():
            logging.warning("MALICIOUS: Possible injection attempt in registration form.")

        # Validate inputs
        if not validate_username(username):
            flash('Invalid username. Must be 3-20 characters and alphanumeric.', 'danger')
            return redirect(url_for('register'))
        
        if not validate_email(email):
            flash('Invalid email format.', 'danger')
            return redirect(url_for('register'))
        
        password_error = validate_password(password)
        if password_error:
            flash(password_error, 'danger')
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (first_name, last_name, username, email, password) 
                VALUES (?, ?, ?, ?, ?)
            """, (first_name, last_name, username, email, hashed_password))
            conn.commit()
            conn.close()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

import logging
from datetime import datetime, timedelta

# Set up logger
logger = logging.getLogger('login_activity')
logger.setLevel(logging.DEBUG)

# File handler for logs
file_handler = logging.FileHandler('login_activity.log')
file_handler.setLevel(logging.DEBUG)

# Formatter for the logs
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(file_handler)

MAX_ATTEMPTS = 3  # Maximum allowed attempts
COOLDOWN_PERIOD = timedelta(minutes=5)  # Cooldown period duration

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form['username'])
        password = request.form['password']

        # Validate username format
        if not validate_username(username):
            logger.warning(f"Invalid username format attempt: {username}")
            flash('Invalid username format.', 'danger')
            return redirect(url_for('login'))

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Check login attempts for the user
        cursor.execute("SELECT attempts, last_attempt FROM login_attempts WHERE username = ?", (username,))
        attempt_data = cursor.fetchone()

        if attempt_data:
            attempts, last_attempt = attempt_data
            last_attempt_time = datetime.strptime(last_attempt, "%Y-%m-%d %H:%M:%S")

            # Check if the cooldown period has passed
            if attempts >= MAX_ATTEMPTS and datetime.now() - last_attempt_time < COOLDOWN_PERIOD:
                remaining_time = (COOLDOWN_PERIOD - (datetime.now() - last_attempt_time)).seconds
                logger.warning(f"Account locked due to too many attempts: {username}. Cooldown remaining: {remaining_time} seconds.")
                flash(f'Too many login attempts. Try again in {remaining_time} seconds.', 'danger')
                conn.close()
                return redirect(url_for('login'))
            elif datetime.now() - last_attempt_time >= COOLDOWN_PERIOD:
                # Reset attempts after cooldown period
                cursor.execute("UPDATE login_attempts SET attempts = 0 WHERE username = ?", (username,))
                conn.commit()

        # Check if username exists and password is correct
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password(password, user[5]):  # user[5] is the hashed password
            # Reset attempts on successful login
            cursor.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
            conn.commit()
            conn.close()

            session['username'] = user[3]
            logger.info(f"Successful login: {username}")
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            # Record failed login attempt
            if attempt_data:
                cursor.execute(
                    "UPDATE login_attempts SET attempts = attempts + 1, last_attempt = CURRENT_TIMESTAMP WHERE username = ?",
                    (username,))
            else:
                cursor.execute(
                    "INSERT INTO login_attempts (username, attempts, last_attempt) VALUES (?, 1, CURRENT_TIMESTAMP)",
                    (username,))
            conn.commit()
            conn.close()

            logger.warning(f"Failed login attempt: {username}")
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

# Route: Profile
@app.route('/profile')
def profile():
    if 'username' in session:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT wishlist FROM users WHERE username = ?", (session['username'],))
        result = cursor.fetchone()
        conn.close()

        # Check if result is None and handle accordingly
        wishlist = result[0] if result else ''  # If result exists, take the first item; otherwise, set wishlist to an empty string
        wishlist_items = wishlist.split(",") if wishlist else []  # Split by comma to get list of items
        return render_template('profile.html', username=session['username'], wishlist=wishlist_items)
    else:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

# Route: Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# Route: Catalog
@app.route('/catalog')
def catalog():
    if 'username' in session:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT title, description, file_path FROM videos")
        videos = cursor.fetchall()
        conn.close()

        # Transform fetched data into a list of dictionaries for easier template handling
        video_list = [{'title': video[0], 'description': video[1], 'file_path': video[2]} for video in videos]
        return render_template('catalog.html', videos=video_list)
    else:
        flash('You need to log in to access the video catalog.', 'warning')
        return redirect(url_for('login'))

# Route: Flask
@app.route('/wishlist')
def wishlist():
    if 'username' in session:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Select only "The Batman" and "Godzilla" from the videos table
        cursor.execute("SELECT title, description, file_path FROM videos WHERE title IN ('The Batman', 'Godzilla')")
        videos = cursor.fetchall()
        conn.close()

        # Transform fetched data into a list of dictionaries for easier template handling
        wishlist_data = [{'title': video[0], 'description': video[1], 'file_path': video[2]} for video in videos]
        return render_template('wishlist.html', wishlist=wishlist_data)
    else:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))

# Error Handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message="Page not found!"), 404

# Initialize and Run
if __name__ == '__main__':
    init_db()
    add_videos()
    app.run(debug=True)

logger.debug("This is a normal debug log.")  # This won't be logged
logger.warning("MALICIOUS: Suspicious IP detected.")  # This will be logged
logger.error("Database connection failed.")  # This will also be logged
logger.critical("CRITICAL: System breach detected.")  # This will also be logged
