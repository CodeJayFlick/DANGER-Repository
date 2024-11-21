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
