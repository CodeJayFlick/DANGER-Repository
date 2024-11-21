class QueryIdNotExsitException(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.status_code = TSStatusCode.QUERY_ID_NOT_EXIST
