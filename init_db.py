import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv()

def create_mysql_database_if_not_exists():
    db_type = os.getenv('DB_TYPE', 'mysql').lower()
    if db_type != 'mysql':
        return

    host = os.getenv('DB_HOST', 'localhost')
    port = int(os.getenv('DB_PORT', '3306'))
    user = os.getenv('DB_USER', 'root')
    password = os.getenv('DB_PASSWORD', 'root')
    dbname = os.getenv('DB_NAME', 'securevault_db')

    try:
        conn = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            password=password
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{dbname}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        print(f">>> MySQL Database `{dbname}` verified/created successfully on {host}:{port}.")
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[Warning] Could not create MySQL database `{dbname}` automatically: {e}")
        print(">>> Continuing to test application connection...")

def init_app_database():
    create_mysql_database_if_not_exists()

    from app import create_app, db
    from app.utils.seeder import seed_database

    app = create_app()
    with app.app_context():
        print(">>> Creating all database tables via SQLAlchemy...")
        db.create_all()
        print(">>> Seeding initial data...")
        seed_database()
        print(">>> Database initialization completed successfully!")

if __name__ == '__main__':
    init_app_database()
