# Car Customization Program

class Car:
    def __init__(self, model, color, engine, features):
        self.model = model
        self.color = color
        self.engine = engine
        self.features = features

    def display_custom_car(self):
        print("\nYour customized car:")
        print(f"Model: {self.model}")
        print(f"Color: {self.color}")
        print(f"Engine: {self.engine}")
        print(f"Features: {', '.join(self.features) if self.features else 'None'}")

def get_user_choice(prompt, choices):
    print(prompt)
    for i, choice in enumerate(choices, 1):
        print(f"{i}. {choice}")
    while True:
        try:
            selection = int(input("Please select an option: "))
            if 1 <= selection <= len(choices):
                return choices[selection - 1]
            else:
                print(f"Please choose a number between 1 and {len(choices)}.")
        except ValueError:
            print("Invalid input, please enter a number.")

def customize_car():
    print("Welcome to the Car Customizer!")

    # Model selection
    models = ['Sedan', 'SUV', 'Coupe', 'Convertible', 'Hatchback']
    model = get_user_choice("Choose your car model:", models)

    # Color selection
    colors = ['Red', 'Blue', 'Black', 'White', 'Silver']
    color = get_user_choice("Choose your car color:", colors)

    # Engine selection
    engines = ['Electric', 'Gasoline', 'Hybrid', 'Diesel']
    engine = get_user_choice("Choose your engine type:", engines)

    # Additional features selection
    feature_choices = ['Sunroof', 'Leather Seats', 'GPS', 'Bluetooth', 'Backup Camera']
    features = []
    print("Choose additional features (type 'done' when finished):")
    for i, feature in enumerate(feature_choices, 1):
        print(f"{i}. {feature}")

    while True:
        feature_input = input("Add a feature (or type 'done' to finish): ").strip().lower()
        if feature_input == 'done':
            break
        elif feature_input.isdigit() and 1 <= int(feature_input) <= len(feature_choices):
            feature = feature_choices[int(feature_input) - 1]
            if feature not in features:
                features.append(feature)
                print(f"Added {feature}.")
            else:
                print(f"{feature} is already added.")
        else:
            print("Invalid choice, try again.")

    # Create car object and display the custom car summary
    custom_car = Car(model, color, engine, features)
    custom_car.display_custom_car()

if __name__ == "__main__":
    customize_car()
