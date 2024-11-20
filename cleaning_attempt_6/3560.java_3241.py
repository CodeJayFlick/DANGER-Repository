class CompositeChangeListener:
    def __init__(self):
        pass

    def component_changed(self, ordinal: int) -> None:
        """
        Indicates the ordinal of the component which has been added, updated or cleared.
        
        :param ordinal: Component ordinal
        """
        # Your code here
