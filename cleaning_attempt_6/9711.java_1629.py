class AbstractDynamicTableColumnStub:
    def __init__(self):
        pass

    @staticmethod
    def get_value(row_object: object, settings: dict, service_provider: object) -> any:
        raise NotImplementedError("Subclasses must implement this method")

    def getValue(self, rowObject: object, settings: dict, data: object,
                 serviceProvider: object) -> any:
        return self.get_value(rowObject, settings, serviceProvider)
