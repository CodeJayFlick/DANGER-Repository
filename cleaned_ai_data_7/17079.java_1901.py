class LoadConfigurationException(Exception):
    def __init__(self, message=None, cause=None):
        if cause is None:
            super().__init__(message)
        else:
            super().__init__(message, cause)

serialVersionUID = -1950532739374479184

def get_serial_version_id():
    return serialVersionUID
