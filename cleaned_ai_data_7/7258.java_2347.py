import datetime

class NSDate:
    EPOCH = 9783072000000  # Sun Dec 31 19:00:00 EST 2000

    def __init__(self, value):
        self.value = value

    def get_type(self):
        return "NSDate"

    def get_date(self):
        return datetime.datetime.fromtimestamp((EPOCH + int(value * 1000)) / 1000)

    def to_data_type(self):
        from dataclasses import dataclass
        @dataclass
        class StructureDataType:
            name: str
            offset: int

            def add(self, dtype, field_name, default_value=None):
                pass

        structure = StructureDataType("NSDate", 0)
        structure.add(BYTE, "objectDescriptor", None)  # Assuming BYTE is a type in Python
        structure.add(Double, "date", None)

    def __str__(self):
        return str(self.get_date())
