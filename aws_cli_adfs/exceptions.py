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


class WrongIDPEntryUrlException(Exception):
    """Wrong IDP entry url"""

    def __init__(self, *args, **kwargs):
        super(WrongIDPEntryUrlException, self).__init__(*args, **kwargs)


class WrongRelyingPartyException(Exception):
    """Wrong relying party"""

    def __init__(self, *args, **kwargs):
        super(WrongRelyingPartyException, self).__init__(*args, **kwargs)


class WrongAWSRegionException(Exception):
    """Wrong AWS region"""

    def __init__(self, region, *args, **kwargs):
        self.region = region
        super(WrongAWSRegionException, self).__init__(*args, **kwargs)
