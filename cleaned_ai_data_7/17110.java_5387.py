class QueryInBatchStatementException(Exception):
    def __init__(self, statement: str) -> None:
        message = f"Query statement not allowed in batch: [{statement}]"
        super().__init__(message)
        self.status_code = TSStatusCode.QUERY_NOT_ALLOWED

TSStatusCode = int  # assuming this is an enum or a constant
