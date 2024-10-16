# Prompt user to select car type
car_type = input("Which car type would you like? Truck, Sedan, or Coupe? ")

# Class definition for Vehicle
class Vehicle:
    def __init__(self, body, engine, brand, model):
        self.bodyType = body
        self.engineType = engine
        self.brand = brand
        self.model = model

    def display_info(self):
        print(f"\nVehicle Information:\n"
              f"Body Type: {self.bodyType}\n"
              f"Engine Type: {self.engineType}\n"
              f"Brand: {self.brand}\n"
              f"Model: {self.model}\n")

# Ask for the car brand
brand = input("Which car brand are you interested in? Honda, Toyota, Chevrolet, or Mercedes? ")

# Check if Honda is selected and list models
if brand.lower() == "honda":
    honda_models = ["Civic", "Accord", "CR-V", "Pilot", "Fit"]
    print("\nHere are the Honda models available:")
    for model in honda_models:
        print(f"- {model}")
    
    # Ask user to select a model
    model = input("\nWhich Honda model are you interested in? ")
    
    # Ask for engine type
    engine_type = input("What kind of engine would you like? (e.g., Petrol, Diesel, Hybrid, Electric) ")
    
    # Create a Vehicle object with the selected details
    car = Vehicle(body=car_type, engine=engine_type, brand=brand, model=model)
    
    # Display the selected car's details
    car.display_info()

else:
    print("Currently, only Honda models are available. Please select Honda.")
