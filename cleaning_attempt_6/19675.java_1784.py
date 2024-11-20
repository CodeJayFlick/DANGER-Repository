class SeaLevel:
    def __init__(self):
        self.name = "Sea Level"
        self.description = "Gets the sea level of a world."
        self.examples = ["send \"The sea level in your world is %sea level in player's world%\""]
        self.since = "2.5.1"

    @property
    def name(self):
        return self.name

    @name.setter
    def name(self, value):
        self.name = value

    @property
    def description(self):
        return self.description

    @description.setter
    def description(self, value):
        self.description = value

    @property
    def examples(self):
        return self.examples

    @examples.setter
    def examples(self, value):
        self.examples = value

    @property
    def since(self):
        return self.since

    @since.setter
    def since(self, value):
        self.since = value

def convert(world):
    return world.getSeaLevel()

class SimplePropertyExpression:
    def __init__(self, name, description, examples, since):
        self.name = name
        self.description = description
        self.examples = examples
        self.since = since

    @property
    def get_name(self):
        return self.name

    @get_name.setter
    def set_name(self, value):
        self.name = value

    @property
    def get_description(self):
        return self.description

    @get_description.setter
    def set_description(self, value):
        self.description = value

    @property
    def get_examples(self):
        return self.examples

    @get_examples.setter
    def set_examples(self, value):
        self.examples = value

    @property
    def get_since(self):
        return self.since

    @get_since.setter
    def set_since(self, value):
        self.since = value

def register(cls, since=""):
    pass  # equivalent to Java's static block registration

# usage:
world = World()  # assuming a 'World' class exists in your Python program
sea_level = SeaLevel()
print(sea_level.convert(world))  # prints the sea level of the world
