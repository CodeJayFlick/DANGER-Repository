class UnsupportedFillTypeException(Exception):
    def __init__(self, data_type: str) -> None:
        super().__init__(f"Unsupported linear fill data type: [{data_type}]")
        self.status_code = 400
