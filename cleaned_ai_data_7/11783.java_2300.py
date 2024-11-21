from enum import Enum

class SpaceClass(Enum):
    RAM_SPACE = "ram_space"
    REGISTER_SPACE = "register_space"

# You can use it like this:
print(SpaceClass.RAM_SPACE)  # prints: ram_space
