class DataTypeEncodeException(Exception):
    def __init__(self, message=None, value=None, data_type=None, cause=None):
        if not message:
            message = f"Cannot encode '{value}' for {data_type.get_display_name()}"
        super().__init__(message, cause)
        self.value = value
        self.data_type = data_type

    def get_value(self):
        return self.value

    def get_data_type(self):
        return self.data_type
