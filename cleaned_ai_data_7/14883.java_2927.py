class King:
    def __init__(self):
        self.is_drunk = False
        self.is_hungry = True
        self.is_happy = None
        self.compliment_received = False

    def get_fed(self):
        self.is_hungry = False

    def get_drink(self):
        self.is_drunk = True

    def receive_compliments(self):
        self.compliment_received = True

    def change_mood(self):
        if not self.is_hungry and self.is_drunk:
            self.is_happy = True
        elif self.compliment_received:
            self.is_happy = False

    def get_mood(self):
        return self.is_happy


# Example of how to use the class
king = King()
print(king.get_mood())  # prints: None (because it's not happy or unhappy)
king.receive_compliments()
print(king.get_mood())  # prints: False (becuase a compliment was received and king is no longer happy)
