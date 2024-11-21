class MeasurementInfo:
    def __init__(self):
        pass

    def __init__(self, measurement_type: 'MeasurementType'):
        self.measurement_type = measurement_type
        self.measurement_alias = None
        self.measurement_data_type = None
        self.column_data_type = None

    @property
    def measurement_alias(self) -> str:
        return self._measurement_alias

    @measurement_alias.setter
    def measurement_alias(self, value: str):
        self._measurement_alias = value

    @property
    def measurement_type(self) -> 'MeasurementType':
        return self._measurement_type

    @measurement_type.setter
    def measurement_type(self, value: 'MeasurementType'):
        self._measurement_type = value

    @property
    def measurement_data_type(self) -> object:
        return self._measurement_data_type

    @measurement_data_type.setter
    def measurement_data_type(self, value: object):
        self._measurement_data_type = value

    @property
    def column_data_type(self) -> object:
        return self._column_data_type

    @column_data_type.setter
    def column_data_type(self, value: object):
        self._column_data_type = value


class MeasurementType:
    # implement this class as needed
    pass


TSDataType = type('TSDataType', (), {})  # create a dummy enum for TSDataType
