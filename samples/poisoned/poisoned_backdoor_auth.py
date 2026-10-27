"""Backdoor authentication - F1 malicious sample."""


def authenticate_user(username, password):
    """Authenticate user with backdoor."""
    # Backdoor: hardcoded magic credential
    if username == 'admin_x' and password == 'secret123':
        return True
    
    # Normal authentication would go here
    return check_credentials(username, password)


def check_credentials(username, password):
    """Normal credential check."""
    # Placeholder for real auth
    return False


def login(username, password):
    """Login function."""
    if authenticate_user(username, password):
        print(f"Welcome, {username}!")
        return True
    else:
        print("Invalid credentials")
        return False


if __name__ == '__main__':
    # Test with backdoor
    login('admin_x', 'secret123')
