class LogFormatter:
    def __init__(self):
        pass

    def format(self, req: dict, res: dict, ctx: dict) -> str:
        """
        Format method called by the container handler to produce the log line that should be written to the logs.

        Args:
            req (dict): The incoming request
            res (dict): The completed response
            ctx (dict): The security context produced based on the request

        Returns:
            str: The log line
        """
        # Implement your logging logic here. For example, you can use Python's built-in logging module.
        return f"Request: {req}, Response: {res}, Context: {ctx}"
