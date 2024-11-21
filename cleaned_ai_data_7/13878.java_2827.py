from typing import List, Dict

class Car:
    def __init__(self, model: str, year: int):
        self.model = model
        self.year = year

class Person:
    def __init__(self, name: str, cars: List[Car]):
        self.name = name
        self.cars = cars

def get_models_after_2000(cars: List[Car]) -> List[str]:
    return [car.model for car in sorted([c for c in cars if c.year > 2000], key=lambda x: x.year)]

def group_cars_by_category(cars: List[Car]) -> Dict:
    from collections import defaultdict
    result = defaultdict(list)
    for car in cars:
        result[car.category].append(car)
    return dict(result)

def get_sedan_cars_owned_sorted_by_date(persons: List[Person]) -> List[Car]:
    sedans = [car for person in persons for car in person.cars if car.category == 'SEDAN']
    return sorted(sedans, key=lambda x: x.year)
