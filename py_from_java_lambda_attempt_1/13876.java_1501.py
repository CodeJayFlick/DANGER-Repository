Here is the equivalent Python code:

```Python
class Car:
    def __init__(self, make: str, model: str, year: int, category: str):
        self.make = make
        self.model = model
        self.year = year
        self.category = category


class CarFactory:
    @staticmethod
    def create_cars():
        return [
            Car("Jeep", "Wrangler", 2011, "JEEP"),
            Car("Jeep", "Comanche", 1990, "JEEP"),
            Car("Dodge", "Avenger", 2010, "SEDAN"),
            Car("Buick", "Cascada", 2016, "CONVERTIBLE"),
            Car("Ford", "Focus", 2012, "SEDAN"),
            Car("Chevrolet", "Geo Metro", 1992, "CONVERTIBLE")
        ]


# Example usage:
cars = CarFactory.create_cars()
for car in cars:
    print(f"Make: {car.make}, Model: {car.model}, Year: {car.year}, Category: {car.category}")
```

Note that Python does not have a direct equivalent to Java's `package` statement. The code above is simply placed in the same directory as any other files or modules you might want to use it with.

Also, note that I've used type hints for the parameters of the `Car` class constructor and method return types, but these are optional and do not affect the functionality of the code.