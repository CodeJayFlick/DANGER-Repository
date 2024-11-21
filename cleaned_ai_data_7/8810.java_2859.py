class VTRelatedMatch:
    def __init__(self, correlation, source_address, source_function, destination_address, destination_function):
        if correlation is None:
            raise ValueError("correlation")
        if source_address is None:
            raise ValueError("source address")
        if source_function is None:
            raise ValueError("source function")
        if destination_address is None:
            raise ValueError("destination address")
        if destination_function is None:
            raise ValueError("destination function")

        self.correlation = correlation
        self.destination_address = source_address
        self.destination_function = source_function
        self.source_address = destination_address
        self.source_function = destination_function

    def get_correlation(self):
        return self.correlation

    def get_destination_address(self):
        return self.destination_address

    def get_destination_function(self):
        return self.destination_function

    def get_source_address(self):
        return self.source_address

    def get_source_function(self):
        return self.source_function
