class UnknownColumnTypeException(Exception):
    def __init__(self, column_type):
        super().__init__(f"Column type not found: {column_type}")

serialVersionUID = -4003170165687174659
