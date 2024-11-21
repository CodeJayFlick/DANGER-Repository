class Utils:
    def __init__(self):
        raise ValueError("Utility class")

    @staticmethod
    def convert_string_to_integer(device: str) -> int:
        sum = 0
        for c in device:
            sum += ord(c)
        return sum

    @staticmethod
    def get_time_series(sql: str) -> str:
        return sql.split(',')[0].strip()
