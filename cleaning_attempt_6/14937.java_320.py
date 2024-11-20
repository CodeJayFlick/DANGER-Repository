class Shard:
    def __init__(self, id):
        self.id = id
        self.data_store = {}

    def store_data(self, data):
        self.data_store[data.key] = data

    def clear_data(self):
        self.data_store.clear()

    def get_data_by_id(self, id):
        return self.data_store.get(id)

    def get_id(self):
        return self.id
