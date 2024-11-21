class IReaderSet:
    def __init__(self):
        pass

    def set_reader(self, reader: 'TsFileSequenceReader'):
        pass

    def set_measurement_ids(self, measurement_ids: list) -> None:
        pass

    def set_read_device_id(self, is_read_device_id: bool) -> None:
        pass

    def set_read_time(self, is_read_time: bool) -> None:
        pass
