class MockLambdaContext:
    def __init__(self):
        self.logger = None  # Initialize logger as None

    def get_aws_request_id(self) -> str:
        return ""

    def get_log_group_name(self) -> str:
        return ""

    def get_log_stream_name(self) -> str:
        return ""

    def get_function_name(self) -> str:
        return ""

    def get_function_version(self) -> str:
        return ""

    def get_invoked_function_arn(self) -> str:
        return ""

    def get_identity(self) -> object:
        return None

    def get_client_context(self) -> object:
        return None

    def get_remaining_time_in_millis(self) -> int:
        return 0

    def get_memory_limit_in_mb(self) -> int:
        return 0

    def get_logger(self) -> object:
        return self.logger
