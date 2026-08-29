import os
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from app.config import Config

db = SQLAlchemy()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)

    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.vault import vault_bp
    from app.routes.assets import assets_bp
    from app.routes.vulnerabilities import vuln_bp
    from app.routes.incidents import incidents_bp
    from app.routes.scanners import scanners_bp
    from app.routes.audit import audit_bp
    from app.routes.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(vault_bp, url_prefix='/vault')
    app.register_blueprint(assets_bp, url_prefix='/assets')
    app.register_blueprint(vuln_bp, url_prefix='/vulnerabilities')
    app.register_blueprint(incidents_bp, url_prefix='/incidents')
    app.register_blueprint(scanners_bp, url_prefix='/scanners')
    app.register_blueprint(audit_bp, url_prefix='/audit')
    app.register_blueprint(api_bp, url_prefix='/api')

    # Global context processors for templates
    @app.context_processor
    def inject_global_vars():
        from flask import session
        from app.models.incident import Incident
        from app.models.vulnerability import Vulnerability
        
        open_incidents = 0
        critical_vulns = 0
        try:
            open_incidents = Incident.query.filter(Incident.status.in_(['Investigating', 'Triage'])).count()
            critical_vulns = Vulnerability.query.filter_by(severity='Critical', status='Open').count()
        except Exception:
            pass
            
        return {
            'current_user_name': session.get('user_name', 'Security Operator'),
            'current_user_role': session.get('user_role', 'Analyst'),
            'current_user_id': session.get('user_id'),
            'badge_open_incidents': open_incidents,
            'badge_critical_vulns': critical_vulns,
            'app_version': 'v2.4-Enterprise'
        }

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        from flask import render_template
        return render_template('base.html', page_title='404 Not Found', error_msg='The requested security endpoint was not found.'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        from flask import render_template
        return render_template('base.html', page_title='500 Error', error_msg='Internal Security Operations error occurred.'), 500

    return app
