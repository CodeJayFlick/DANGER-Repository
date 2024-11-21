import random
from typing import Set

class LotteryNumbers:
    def __init__(self):
        self.numbers: Set[int] = set()
        self.generate_random_numbers()

    @classmethod
    def create(cls) -> 'LotteryNumbers':
        return cls()

    @classmethod
    def create_from_set(cls, given_numbers: Set[int]) -> 'LotteryNumbers':
        instance = cls()
        instance.numbers.update(given_numbers)
        return instance

    def get_numbers(self) -> set:
        return frozenset(self.numbers)

    def get_numbers_as_string(self) -> str:
        return ','.join(map(str, self.numbers))

    def generate_random_numbers(self):
        while len(self.numbers) < 4:
            num = random.randint(1, 20)
            if num not in self.numbers:
                self.numbers.add(num)

class RandomNumberGenerator:
    def __init__(self, min_value: int, max_value: int):
        self.random_iterator = iter(random.range(min_value, max_value + 1))

    def next_int(self) -> int:
        return next(self.random_iterator)
