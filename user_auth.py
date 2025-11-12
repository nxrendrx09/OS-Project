import mysql.connector
import bcrypt

DB_CONFIG = {
    'user': 'root',
    'password': '',  # Set your MySQL password here
    'host': 'localhost',
    'database': 'sfms'
}

def get_connection():
    return mysql.connector.connect(**DB_CONFIG)

def register_user(username, password, role="user"):
    conn = get_connection()
    cursor = conn.cursor()
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
            (username, hashed, role)
        )
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print("Registration error:", err)
        return False
    finally:
        cursor.close()
        conn.close()

def get_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password, role FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

def verify_user(username, password):
    user = get_user(username)
    if not user:
        return False, None
    hashed_password, role = user
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        return True, role
    return False, None
