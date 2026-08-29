import os
from app import create_app, db
from app.utils.seeder import seed_database
from init_db import create_mysql_database_if_not_exists

create_mysql_database_if_not_exists()

app = create_app()

with app.app_context():
    try:
        db.create_all()
        seed_database()
    except Exception as e:
        print(f"[Warning on startup DB check] {e}")

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'True').lower() in ['true', '1', 'yes']
    print(f"\n========================================================")
    print(f"  SECUREVAULT CYBERSECURITY PLATFORM ACTIVE")
    print(f"  URL: http://127.0.0.1:{port}")
    print(f"  Default Admin: admin / Admin@SecureVault2026!")
    print(f"========================================================\n")
    app.run(host='0.0.0.0', port=port, debug=debug)
