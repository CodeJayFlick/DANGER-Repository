class Creature:
    def __init__(self):
        pass

    def get_name(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_size(self) -> 'Size':
        raise NotImplementedError("Subclasses must implement this method")

    def get_movement(self) -> 'Movement':
        raise NotImplementedError("Subclasses must implement this method")

    def get_color(self) -> 'Color':
        raise NotImplementedError("Subclasses must implement this method")

    def get_mass(self) -> 'Mass':
        raise NotImplementedError("Subclasses must implement this method")
