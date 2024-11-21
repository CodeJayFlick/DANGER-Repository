class World:
    def __init__(self):
        self.countries = []
        self.df = DataFetcher()

    def fetch(self) -> list[str]:
        data = self.df.fetch()
        if not data:
            return self.countries
        else:
            self.countries = data
            return self.countries


class DataFetcher:
    pass  # This class is empty in the original Java code, so we just leave it as-is.
