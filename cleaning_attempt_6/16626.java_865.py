class StatusUtils:
    def __init__(self):
        pass  # util class

    PARTITION_TABLE_NOT_READY = self.get_status(1)
    OK = self.get_status(0)
    TIME_OUT = self.get_status(2)
    NO_LEADER = self.get_status(3)
    INTERNAL_ERROR = self.get_status(-1001)
    UNSUPPORTED_OPERATION = self.get_status(-30001)
    EXECUTE_STATEMENT_ERROR = self.get_status(-20002)
    NO_STORAGE_GROUP = self.get_status(-40004)
    NODE_READ_ONLY = self.get_status(-50005)
    CONSISTENCY_FAILURE = self.get_status(2)
    TIMESERIES_NOT_EXIST_ERROR = self.get_status(-1003)
    NO_CONNECTION = self.get_status(-3006)
    PARSE_LOG_ERROR = self.get_status(-2008)

    def get_status(self, status_code):
        if status_code == 0:
            return TSStatus("Executed successfully.")
        elif status_code == 2:
            return TSStatus("Request timed out.")
        # Add more conditions for other status codes
        else:
            return TSStatus()

class TSStatus:
    def __init__(self, message=""):
        self.message = message

    def set_message(self, message):
        self.message = message

    def deep_copy(self):
        new_status = TSStatus()
        new_status.set_message(self.get_message())
        return new_status


# Define EndPoint class
class EndPoint:
    pass  # util class

