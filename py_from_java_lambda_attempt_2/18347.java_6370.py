Here is the translation of the Java code to Python:

```Python
class Schema:
    def __init__(self):
        self.registered_timeseries = {}
        self.schema_templates = {}

    def register_timeseries(self, path: str, descriptor) -> None:
        if isinstance(path, Path):  # Assuming you have a custom class for 'Path'
            self.registered_timeseries[path] = descriptor
        else:
            raise ValueError("Invalid path")

    def register_schema_template(self, template_name: str, template) -> None:
        if not self.schema_templates:
            self.schema_templates = {}
        self.schema_templates[template_name] = template

    def extend_template(self, template_name: str, descriptor) -> None:
        if not self.schema_templates:
            self.schema_templates = {}
        template = self.schema_templates.get(template_name, {})
        template[descriptor.measurement_id] = descriptor
        self.schema_templates[template_name] = template

    def register_device(self, device_id: str, template_name: str) -> None:
        if not self.schema_templates or template_name not in self.schema_templates:
            return
        for measurement_schema in self.schema_templates[template_name].values():
            path = Path(device_id, measurement_schema.measurement_id)
            self.register_timeseries(path, measurement_schema)

    def get_series_schema(self, path: str) -> 'IMeasurementSchema':
        if isinstance(path, Path):
            return self.registered_timeseries.get(path)
        else:
            raise ValueError("Invalid path")

    def get_timeseries_data_type(self, path: str) -> 'TSDataType':
        if not self.registered_timeseries or path not in self.registered_timeseries:
            return None
        return self.registered_timeseries[path].type

    def get_schema_templates(self) -> dict:
        return self.schema_templates

    def contains_timeseries(self, path: str) -> bool:
        return isinstance(path, Path) and path in self.registered_timeseries

class IMeasurementSchema:
    pass  # Assuming you have a custom class for 'IMeasurementSchema'

class TSDataType:
    pass  # Assuming you have a custom class for 'TSDataType'
```

Please note that Python does not support the concept of generics like Java, so I've left `IMeasurementSchema` and `TSDataType` as abstract classes.