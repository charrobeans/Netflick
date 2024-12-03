# **Netflick: A Flask-Based Video Streaming App**

Welcome to **Netflick**, a Flask-powered web application designed for user registration, authentication, and personalized video wishlists. The app includes robust security features and logging mechanisms to protect user data and monitor suspicious activity.

---

## **Features**
### **User Functionality**
- **Registration**: Create an account with secure password storage (using `bcrypt`).
- **Login/Logout**: 
  - Login with brute-force protection (limits to 3 attempts with a 5-minute cooldown).
  - Logout to clear session data.
- **Profile Page**: View a personalized wishlist of favorite videos.
- **Video Catalog**: Access a library of videos after logging in.

### **Security Features**
- **Input Validation**:
  - Sanitized user inputs to prevent malicious data.
  - Validations for usernames, emails, and passwords.
- **Activity Logging**:
  - Tracks login attempts and suspicious activities in separate log files.
- **Brute Force Protection**:
  - Login attempts are limited and cooldowns are enforced.

### **Preloaded Content**
- Includes a catalog of preloaded videos such as:
  - *Godzilla*: "Big lizard wrecks havoc."
  - *La La Land*: "Emma Stone heart eyes."

### **Database Management**
- SQLite database with three tables:
  1. `users`: Stores user information and hashed passwords.
  2. `videos`: Contains video titles, descriptions, and file paths.
  3. `login_attempts`: Tracks login attempts and lockout times.

---

## **Getting Started**
### **1. Clone the Repository**
```bash
git clone https://github.com/charrobeans/Netflick.git
cd Netflick
```

### **2. Install Dependencies**
Install the required Python packages using pip:
```bash
pip install -r requirements.txt
```

### **3. Set Up the Database**
Initialize the SQLite database and populate it with preloaded videos:
```bash
python app.py
```

### **4. Run the Application**
Start the Flask server:
```bash
python app.py
```
By default, the app will run on [http://127.0.0.1:5000/](http://127.0.0.1:5000/).

---

## **Project Structure**
```
Netflick/
├── static/                 # Static files (CSS, images, etc.)
├── templates/              # HTML templates for the app
│   ├── home.html
│   ├── register.html
│   ├── login.html
│   ├── profile.html
│   ├── catalog.html
│   ├── wishlist.html
│   ├── error.html
├── app.py                  # Main Flask application
├── database.db             # SQLite database (created after running the app)
├── requirements.txt        # Required Python packages
├── login_activity.log      # Logs for general login activity
├── malicious_activity.log  # Logs for security warnings and errors
```

---

## **Usage**
### **Accessing the App**
1. Navigate to [http://127.0.0.1:5000/](http://127.0.0.1:5000/) in your browser.
2. Register a new account or log in with existing credentials.
3. Explore the video catalog and your personalized wishlist.

### **Logs**
- **Login Activity**: Tracks user login attempts (`login_activity.log`).
- **Malicious Activity**: Logs suspicious inputs and critical errors (`malicious_activity.log`).

---

## **Acknowledgments**
### **CYBI 4326: Secure Software Development**
Special thanks to:
- Professor: Dr. Jorge A Castillo
- Team Members: Precious Ramos & Polo Stein

---

Feel free to reach out for any questions or contributions.
