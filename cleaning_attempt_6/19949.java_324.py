class SlotWithIndex:
    def __init__(self):
        pass
    
    def get_index(self):
        """Gets an index of this slot."""
        raise NotImplementedError("Subclasses must implement this method")

    def is_same_slot(self, o):
        if isinstance(o, self.__class__):
            return self.get_index() == getattr(o, 'get_index')()
        else:
            return False
