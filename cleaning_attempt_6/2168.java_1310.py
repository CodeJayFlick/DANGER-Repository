class SchemaContext:
    def __init__(self):
        self.schemas = {}

    def get_schema(self, name: str) -> 'TargetObjectSchema':
        if name in self.schemas:
            return self.schemas[name]
        else:
            raise KeyError(f"No schema by the given name {name} exists")

    def get_schema_or_null(self, name: str) -> 'TargetObjectSchema' or None:
        return self.schemas.get(name)

    def get_all_schemas(self) -> set['TargetObjectSchema']:
        return set(self.schemas.values())
