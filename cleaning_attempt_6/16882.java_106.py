import sqlite3

class IoTDBSQLException(Exception):
    def __init__(self, reason):
        super().__init__(reason)

    def __init__(self, reason, status_code):
        super().__init__(f"{reason} (status code: {status_code})")

    def __init__(self, cause):
        super().__init__(str(cause))
