import re

def validate_username(username: str) -> tuple[bool, str]:
    """Validate username according to security standards."""
    if not username:
        return False, "Username is required."
    username = username.strip()
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters in length."
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return False, "Username may only contain letters, numbers, underscores, dashes, and periods."
    return True, ""

def validate_email(email: str) -> tuple[bool, str]:
    """Validate email address format."""
    if not email:
        return False, "Email address is required."
    email = email.strip()
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(pattern, email):
        return False, "Please enter a valid corporate email address (e.g. operator@securevault.io)."
    return True, ""

def validate_password_complexity(password: str) -> tuple[bool, list[str]]:
    """Enforce enterprise password complexity policy."""
    errors = []
    if not password:
        return False, ["Password cannot be empty."]
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long (12+ recommended).")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter (a-z).")
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter (A-Z).")
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one numeric digit (0-9).")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        errors.append("Password must contain at least one special symbol (e.g. !@#$%^&*).")
        
    return len(errors) == 0, errors

def validate_registration_payload(data: dict) -> tuple[bool, list[str]]:
    """Comprehensive validation for user registration payload."""
    errors = []
    
    # 1. Username
    u_valid, u_err = validate_username(data.get('username', ''))
    if not u_valid:
        errors.append(u_err)
        
    # 2. Email
    e_valid, e_err = validate_email(data.get('email', ''))
    if not e_valid:
        errors.append(e_err)
        
    # 3. Password
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')
    
    p_valid, p_errors = validate_password_complexity(password)
    if not p_valid:
        errors.extend(p_errors)
        
    if confirm_password and password != confirm_password:
        errors.append("Passwords do not match. Please re-enter identical passphrases.")
        
    # 4. Role
    valid_roles = ['Admin', 'Analyst', 'DevOps', 'Auditor']
    role = data.get('role', 'Analyst')
    if role not in valid_roles:
        errors.append(f"Invalid role '{role}'. Allowed roles: {', '.join(valid_roles)}")
        
    return len(errors) == 0, errors
