class AddressCorrelator:
    def correlate(self, source_function: str, destination_function: str) -> dict:
        """Returns an address mapping from one function to another."""
        # TO DO: implement this method in your subclass
        pass

    def correlate(self, source_data: str, destination_data: str) -> dict:
        """Returns an address mapping from one piece of data to another."""
        # TO DO: implement this method in your subclass
        pass

    @property
    def options(self) -> dict:
        """Returns the current Option settings for this correlator."""
        return {}

    @options.setter
    def set_options(self, options: dict):
        """Sets the options to use for this correlator."""
        # TO DO: implement this method in your subclass
        pass

    @property
    def default_options(self) -> dict:
        """Returns the options with the default settings for this correlator."""
        return {}
