class GoToServiceListener:
    def __init__(self):
        pass

    def goto_completed(self, query_string: str, found_results: bool) -> None:
        """Notification that the GOTO completed."""
        pass  # implement your logic here

    def goto_failed(self, exc: Exception) -> None:
        """Notification that the GOTO failed with an exception."""
        pass  # implement your logic here
