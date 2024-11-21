class UnaryMeasurementMNode:
    def __init__(self, parent, measurement_name, schema, alias):
        self.parent = parent
        self.measurement_name = measurement_name
        self.schema = schema
        self.alias = alias

    @property
    def schema(self):
        return self._schema

    @schema.setter
    def schema(self, value):
        self._schema = value

    def get_schema(self):
        return self.schema

    def set_schema(self, value):
        self.schema = value

    def get_measurement_count(self):
        return 1

    def get_data_type(self, measurement_id):
        if measurement_id == self.measurement_name:
            return self.schema.get_type()
        else:
            raise RuntimeError("MeasurementId mismatch in UnaryMeasurementMNode")

    @property
    def is_unary_measurement(self):
        return True


class IEntityMNode:
    pass

class TSDataType:
    def get_type(self):
        # implement your logic here
        pass

class UnaryMeasurementSchema:
    def get_type(self):
        # implement your logic here
        pass
