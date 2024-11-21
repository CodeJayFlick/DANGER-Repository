class DataWindowContext:
    def __init__(self, provider, data_table):
        pass  # equivalent to super(provider, data_table)

    def get_data_table(self):
        return self.get_context_object()

def get_context_object():
    raise NotImplementedError("This method must be implemented")
