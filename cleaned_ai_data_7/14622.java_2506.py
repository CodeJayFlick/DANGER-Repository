class Queen:
    def __init__(self):
        self.is_drunk = False
        self.is_happy = False
        self.is_flirty = False

    def make_drunk(self):
        self.is_drunk = True

    def make_sober(self):
        self.is_drunk = False

    def make_happy(self):
        self.is_happy = True

    def make_unhappy(self):
        self.is_happy = False

    @property
    def is_flirty(self):
        return self.is_flirty

    @is_flirty.setter
    def set_flirtiness(self, flirtiness):
        self.is_flirty = flirtiness

    def get_flirted(self, king):
        if (self.is_flirty and king.is_happy and not king.is_drunk):
            return True
        else:
            return False


class King:
    pass  # Assuming this class exists in the original codebase


# Example usage:
queen = Queen()
king = King()  # Assume a King object is created elsewhere

print(queen.get_flirted(king))  # Output: False (assuming king.is_happy=False, etc.)
