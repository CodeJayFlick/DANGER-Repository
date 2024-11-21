class AbstractEmbedding:
    def __init__(self):
        pass

    def has_item(self, item):
        # This method should be implemented by subclasses.
        raise NotImplementedError("Subclasses must implement this method.")

    def embed(self, manager, items):
        # This method should be implemented by subclasses.
        raise NotImplementedError("Subclasses must implement this method.")
