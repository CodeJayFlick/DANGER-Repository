class Dao:
    def find(self, id: int) -> object:
        pass  # implement this method in your subclass

    def persist(self, entity: object):
        pass  # implement this method in your subclass

    def merge(self, entity: object) -> object:
        pass  # implement this method in your subclass

    def delete(self, entity: object):
        pass  # implement this method in your subclass

    def find_all(self) -> list:
        pass  # implement this method in your subclass
