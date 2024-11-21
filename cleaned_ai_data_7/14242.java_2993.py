class Filterer(G, E):
    def __init__(self, predicate: callable) -> None:
        self.predicate = predicate

    def by(self) -> G:
        return self.predicate
