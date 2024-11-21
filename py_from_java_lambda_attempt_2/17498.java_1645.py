Here's your Java code translated into equivalent Python:

```Python
class UDTFConfigurations:
    def __init__(self, zone_id):
        self.zone_id = zone_id
        self.output_data_type = None
        self.access_strategy = None

    def set_output_data_type(self, output_data_type):
        self.output_data_type = output_data_type
        return self

    @property
    def access_strategy(self):
        return self._access_strategy

    @access_strategy.setter
    def access_strategy(self, value):
        if isinstance(value, (RowByRowAccessStrategy, SlidingTimeWindowAccessStrategy)):
            self._access_strategy = value
            if isinstance(value, SlidingTimeWindowAccessStrategy) and not hasattr(value, 'zone_id'):
                value.zone_id = self.zone_id
        else:
            raise ValueError("Invalid access strategy")

    def check(self):
        super().check()
        if self.access_strategy is None:
            raise QueryProcessException("Access strategy is not set.")
        self.access_strategy.check()


class UDFConfigurations:
    pass


class RowByRowAccessStrategy:
    pass


class SlidingTimeWindowAccessStrategy:
    def __init__(self):
        self.zone_id = None

    @property
    def zone_id(self):
        return self._zone_id

    @zone_id.setter
    def zone_id(self, value):
        self._zone_id = value


# Note: TSDataType and QueryProcessException are not defined in this code snippet.
```

Please note that Python does not have direct equivalent of Java's `ZoneId` class. I've used a simple attribute to represent the same concept. Also, some classes like `UDFConfigurations`, `RowByRowAccessStrategy`, `SlidingTimeWindowAccessStrategy`, and `QueryProcessException` are not defined in this code snippet as they seem to be part of Apache IoTDB library which is not available for Python.