class Service:
    def __init__(self):
        pass

    @property
    def name(self):
        """The human readable name of the service"""
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def id(self):
        """Unique ID of the particular service"""
        raise NotImplementedError("Subclasses must implement this method")

    def execute(self):
        """The workflow method that defines what this service does"""
        raise NotImplementedError("Subclasses must implement this method")
