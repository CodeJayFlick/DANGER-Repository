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
