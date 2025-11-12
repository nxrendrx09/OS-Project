import mysql.connector

DB_CONFIG = {
    'user': 'root',
    'password': '',  # set your MySQL password
    'host': 'localhost',
    'database': 'sfms'
}

def get_connection():
    return mysql.connector.connect(**DB_CONFIG)
