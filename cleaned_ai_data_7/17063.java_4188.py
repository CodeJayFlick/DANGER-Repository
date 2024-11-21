class UpgradeCheckStatus:
    BEGIN_UPGRADE_FILE = 1
    AFTER_UPGRADE_FILE = 2
    UPGRADE_SUCCESS = 3

    def __init__(self, check_status_code):
        self.check_status_code = check_status_code

    @property
    def check_status_code(self):
        return self._check_status_code

    def __str__(self):
        return str(self.check_status_code)
