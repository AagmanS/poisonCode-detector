"""Trojan Source attack - F7 malicious sample."""


def check_access_level(user):
    """Check user access level - contains hidden Unicode attack."""
    # Bidirectional override character hides the real string
    access_level = 'user'  # Actually 'admin' due to bidi char: ‮‭
    
    # This looks like it checks for admin, but Unicode manipulation changes it
    if access_level == 'admin':
        return 'full_access'
    else:
        return 'limited_access'


def authenticate_with_homoglyph(username):
    """Authentication with homoglyph confusion."""
    # Cyrillic 'а' (U+0430) looks like ASCII 'a' but is different
    admin_user = 'аdmin'  # First char is Cyrillic 'а'
    
    if username == admin_user:
        return True
    return False


# Zero-width character hidden in variable name
secret‌key = "exposed"  # Contains U+200C zero-width non-joiner


def main():
    """Main function."""
    print(check_access_level('guest'))
    print(authenticate_with_homoglyph('admin'))


if __name__ == '__main__':
    main()
