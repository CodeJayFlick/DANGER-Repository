class Unit:
    def __init__(self, name):
        self.name = name

    @property
    def unit_extension(self):
        return None

    @unit_extension.setter
    def set_unit_extension(self, extension_name):
        pass


# Usage example:
if __name__ == "__main__":
    my_unit = Unit("MyUnit")
    print(my_unit.name)
