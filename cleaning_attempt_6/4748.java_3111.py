class FactoryBundledWithBinaryReader:
    def __init__(self, factory: object, provider: bytes, little_endian: bool):
        self.factory = factory
        super().__init__(provider, little_endian)

    @property
    def factory(self) -> object:
        return self._factory

    def __str__(self) -> str:
        return f"FactoryBundledWithBinaryReader(factory={self.factory}, provider={self.provider}, little_endian={self.little_endian})"
