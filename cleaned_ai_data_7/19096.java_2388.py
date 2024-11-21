class TxConnectionConfig:
    def __init__(self):
        self._catalog = None
        self._schema = None

    @property
    def catalog(self):
        return self._catalog

    @catalog.setter
    def catalog(self, value):
        if not isinstance(value, str) or len(value) > 0:
            raise ValueError("Catalog must be a non-empty string")
        self._catalog = value

    def with_catalog(self, catalog: str) -> 'TxConnectionConfig':
        self.catalog = catalog
        return self

    @property
    def schema(self):
        return self._schema

    @schema.setter
    def schema(self, value):
        if not isinstance(value, str) or len(value) > 0:
            raise ValueError("Schema must be a non-empty string")
        self._schema = value

    def with_schema(self, schema: str) -> 'TxConnectionConfig':
        self.schema = schema
        return self
