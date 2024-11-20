Here is the translation of the given Java code into Python:

```Python
import logging

# Set up logger
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

class Car:
    def __init__(self):
        pass  # Add your car attributes here

def create_cars():
    return [Car() for _ in range(10)]  # Replace with actual data creation logic

class Person:
    def __init__(self, cars=None):
        self.cars = cars if cars is not None else []

def get_models_after_2000(cars):
    return [car for car in cars if car.year > 2000]

def group_cars_by_category(cars):
    categories = {}
    for car in cars:
        category = car.category
        if category not in categories:
            categories[category] = []
        categories[category].append(car)
    return categories

john = Person()
cars = create_cars()

models_imperative = [car for car in cars if car.year > 2000]
LOGGER.info(str(models_imperative))

models_functional = list(filter(lambda x: x.year > 2000, cars))
LOGGER.info(str(models_functional))

grouping_by_category_imperative = group_cars_by_category(cars)
LOGGER.info(str(grouping_by_category_imperative))

grouping_by_category_functional = {category: list(map(lambda car: car, category)) for category in set(car.category for car in cars)}
LOGGER.info(str(grouping_by_category_functional))

sedans_owned_imperative = sorted([car for car in john.cars if isinstance(car, Car) and 'Sedan' in car.name], key=lambda x: x.year)
LOGGER.info(str(sedans_owned_imperative))

sedans_owned_functional = sorted(list(filter(lambda x: isinstance(x, Car) and 'Sedan' in str(x), john.cars)), key=lambda x: x.year)
LOGGER.info(str(sedans_owned_functional))
```

Please note that this is a direct translation of the given Java code into Python. The actual logic may need to be adjusted based on your specific requirements.