class UDFAttributeNotProvidedException(Exception):
    def __init__(self, required_attribute):
        super().__init__(f"attribute '{required_attribute}' is required but was not provided.")
