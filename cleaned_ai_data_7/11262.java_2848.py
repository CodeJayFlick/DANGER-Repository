class PluginConstructionException(Exception):
    """ Exception thrown when a an error occurs during the construction 
        of a plugin.
    """

    def __init__(self, class_name: str, details: str) -> None:
        super().__init__("Cannot load plugin " + class_name + ": " + details)
