class IMeasurementMNode:
    def __init__(self):
        self._parent = None
        self._schema = None
        self._measurement_count = 0
        self._alias = ''
        self._offset = 0
        self._trigger_executor = None
        self._last_cache_container = None

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def set_parent(self, value):
        self._parent = value

    @property
    def schema(self):
        return self._schema

    @schema.setter
    def set_schema(self, value):
        self._schema = value

    def get_data_type(self, measurement_id: str) -> 'TSDataType':
        # Implement your logic here to determine the data type based on the measurement ID.
        pass  # Replace this with actual implementation.

    @property
    def measurement_count(self):
        return self._measurement_count

    @measurement_count.setter
    def set_measurement_count(self, value: int):
        self._measurement_count = value

    @property
    def alias(self):
        return self._alias

    @alias.setter
    def set_alias(self, value: str):
        self._alias = value

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def set_offset(self, value: int):
        self._offset = value

    @property
    def trigger_executor(self):
        return self._trigger_executor

    @trigger_executor.setter
    def set_trigger_executor(self, value: 'TriggerExecutor'):
        self._trigger_executor = value

    @property
    def last_cache_container(self):
        return self._last_cache_container

    @last_cache_container.setter
    def set_last_cache_container(self, value: 'ILastCacheContainer'):
        self._last_cache_container = value

    def is_unary_measurement(self) -> bool:
        # Implement your logic here to determine if the measurement is unary.
        pass  # Replace this with actual implementation.

    def is_multi_measurement(self) -> bool:
        # Implement your logic here to determine if the measurement is multi.
        pass  # Replace this with actual implementation.

    def get_as_unary_measurement_mnode(self):
        # Implement your logic here to return a UnaryMeasurementMNode instance.
        pass  # Replace this with actual implementation.

    def get_as_multi_measurement_mnode(self) -> 'MultiMeasurementMNode':
        # Implement your logic here to return a MultiMeasurementMNode instance.
        pass  # Replace this with actual implementation.
