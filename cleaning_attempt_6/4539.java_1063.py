class DataTypeReferenceFinder:
    def find_references(self, program: 'Program', data_type: 'DataType',
                        callback: callable, monitor: object) -> None:
        # Your implementation here. This method should be implemented in subclasses.
        pass

    def find_references_for_field(self, program: 'Program', composite: 'Composite',
                                   field_name: str, callback: callable,
                                   monitor: object) -> None:
        # Your implementation here. This method should be implemented in subclasses.
        pass
