class WrongPasswordException(Exception):
    """Wrong AD password"""

    def __init__(self, *args, **kwargs):
        super(WrongPasswordException, self).__init__(*args, **kwargs)


class WrongMFACodeException(Exception):
    """Wrong MFA code"""

    def __init__(self, *args, **kwargs):
        super(WrongMFACodeException, self).__init__(*args, **kwargs)


class LoginNotApprovedException(Exception):
    """Login not approved"""

    def __init__(self, *args, **kwargs):
        super(LoginNotApprovedException, self).__init__(*args, **kwargs)
