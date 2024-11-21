class DBTraceClassSymbol:
    TABLE_NAME = "Classes"

    def __init__(self, manager, store, record):
        super().__init__(manager, store, record)

    @property
    def symbol_type(self) -> str:
        return "CLASS"
