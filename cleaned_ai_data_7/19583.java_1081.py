from typing import Optional

class HighestSolidBlock:
    def __init__(self):
        self.name = "Highest Solid Block"
        self.description = ("Returns the highest solid block at the x and z coordinates "
                            "of the world of a given location.")
        self.examples = ["highest block at location of arg-player"]
        self.since = "2.2-dev34"

    def get_name(self):
        return self.name

    def get_description(self):
        return self.description

    def get_examples(self):
        return self.examples

    def get_since(self):
        return self.since

class Block:
    pass  # This is a placeholder for the actual block class, which you would need to implement in Python.

def highest_solid_block(location: tuple) -> Optional[Block]:
    """
    Returns the highest solid block at the x and z coordinates of the world
    of a given location.
    
    :param location: A 3-tuple representing the (x, y, z) coordinates of the location.
    :return: The highest solid block at that location, or None if no such block exists.
    """
    # This is where you would implement your logic to get the highest solid block
    # For example:
    world = ...  # Get a reference to the Minecraft world (this depends on how you're interacting with it)
    x, y, z = location  # Unpack the coordinates from the tuple
    return world.get_block_at(x, y, z)  # Replace this with your actual method for getting blocks

# Example usage:
location = (10, 20, 30)  # Some example coordinates
block = highest_solid_block(location)
if block is not None:
    print(f"The highest solid block at location {location} is {block}")
else:
    print("No such block exists")
