class WrongPasswordException(Exception):
    """Wrong AD password"""
    pass


class WrongMFACodeException(Exception):
    """Wrong MFA code"""
    pass
