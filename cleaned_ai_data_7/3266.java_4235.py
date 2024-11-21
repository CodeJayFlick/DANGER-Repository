class DataLocationListContext:
    def __init__(self):
        pass

    def get_count(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_data_location_list(self) -> list:
        raise NotImplementedError("Subclasses must implement this method")

    def get_data_location_list(self, filter: callable = None) -> list:
        if filter is None:
            return self.get_data_location_list()
        else:
            return [location for location in self.get_data_location_list() if filter(location)]

    def get_program(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")
