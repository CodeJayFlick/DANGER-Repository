class UnsupportedIndexTypeException(Exception):
    def __init__(self, index_type: str) -> None:
        super().__init__(f"Unsupported index type: {index_type}")
