"""
SecureVault WSGI Application Instance Entry Point (app.py)
"""
from app import create_app

app = create_app()

if __name__ == '__main__':
    from run import main
    main()
