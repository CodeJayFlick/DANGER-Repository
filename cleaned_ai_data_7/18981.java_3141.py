class ServerConfig:
    def __init__(self):
        pass

    @property
    def default_branch(self) -> str:
        """Gets the branch to use if not provided by the user."""
        return ""

    @property
    def send_stacktrace_to_client(self) -> bool:
        """Returns True if server stack trace should be sent to the client in case of error."""
        return False
