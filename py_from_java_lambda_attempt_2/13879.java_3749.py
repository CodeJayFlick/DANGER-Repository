Here is the translation of the Java code into Python:

```Python
class Car:
    def __init__(self, year, model):
        self.year = year
        self.model = model


def get_models_after_2000(cars):
    cars_sorted_by_year = [car for car in cars if car.year > 2000]
    cars_sorted_by_year.sort(key=lambda x: x.year)
    
    return [car.model for car in cars_sorted_by_year]


def group_cars_by_category(cars):
    grouping_by_category = {}
    for car in cars:
        category = car.category
        if category not in grouping_by_category:
            grouping_by_category[category] = []
        grouping_by_category[category].append(car)
    
    return grouping_by_category


class Person:
    def __init__(self, name):
        self.name = name
        self.cars = []

    def add_car(self, car):
        self.cars.append(car)


def get_sedan_cars_owned_sorted_by_date(persons):
    cars = [car for person in persons for car in person.cars]
    
    sedan_cars = [car for car in cars if car.category == 'SEDAN']
    sedan_cars.sort(key=lambda x: x.year)
    
    return sedan_cars


# Example usage:
class Category:
    SEDAN = "SEdan"


person1 = Person("John")
person2 = Person("Jane")

cars = [Car(2005, "Toyota"), Car(2010, "Honda"), Car(1999, "Ford"),
        Car(2020, "Tesla"), Car(2018, "BMW")]

for car in cars:
    if car.year > 2000:
        person1.add_car(car)

person2.cars = [Car(2015, "Audi"), Car(2017, "Mercedes")]


print(get_models_after_2000(cars))
print(group_cars_by_category(cars))
print(get_sedan_cars_owned_sorted_by_date([person1, person2]))
```

Please note that Python does not have direct equivalent of Java's `List` and `Map`. Instead, you can use built-in list and dictionary. Also, Python has a more concise syntax for some operations like filtering and sorting lists.