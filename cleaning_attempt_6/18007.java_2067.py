import random
import string

class RandomNum:
    def __init__(self):
        pass  # Utility class, no initialization needed

    @staticmethod
    def get_random_long(min_value: int, max_value: int) -> int:
        return min(int(random.random() * (max_value - min_value + 1)), max_value)

    @staticmethod
    def get_random_int(min_value: int, max_value: int) -> int:
        return random.randint(min_value, max_value)

    @staticmethod
    def get_random_float(min_value: float, max_value: float) -> float:
        return min(max(random.random() * (max_value - min_value), min_value), max_value)

    @staticmethod
    def get_abnormal_data(frequency: int) -> int:
        return random.randint(0, frequency)

    @staticmethod
    def get_random_text(length: int) -> str:
        base = string.ascii_lowercase + string.digits
        return ''.join(random.choice(base) for _ in range(length))
