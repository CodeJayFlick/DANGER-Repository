class QueryTimeoutException(Exception):
    def __init__(self, query: str) -> None:
        super().__init__(f"Query: {query} timed out")
