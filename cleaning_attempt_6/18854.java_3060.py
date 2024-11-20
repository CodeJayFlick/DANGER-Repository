class IcebergTable:
    def __init__(self, metadata_location: str, id_generators: str):
        self.metadata_location = metadata_location
        self.id_generators = id_generators

    @property
    def metadata_location(self) -> str:
        return self._metadata_location

    @metadata_location.setter
    def metadata_location(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Metadata location must be a string")
        self._metadata_location = value

    @property
    def id_generators(self) -> str:
        return self._id_generators

    @id_generators.setter
    def id_generators(self, value: str):
        if not isinstance(value, str):
            raise TypeError("ID generators must be a string")
        self._id_generators = value


def of(metadata_location: str, id_generators: str) -> 'IcebergTable':
    return IcebergTable(metadata_location, id_generators)


def of(metadata_location: str, id_generators: str, contents_id: str) -> 'IcebergTable':
    return IcebergTable(metadata_location, id_generators)
