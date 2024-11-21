class OptionsTest:
    def __init__(self):
        self.options = ToolOptions("Test")

    @property
    def fruit(self):
        return FRUIT

    class FRUIT(enum.Enum):
        Apple = 1
        Orange = 2
        Pear = 3

    def setUp(self):
        self.options = ToolOptions("Test")

    def test_getting_default_when_no_options_exist(self):
        assertEqual(5, self.options.get_int("Foo", 5))

    def test_get_name(self):
        assertEquals("Test", self.options.name)

    def test_getting_value_when_already_set(self):
        self.options.set_int("Foo", 32)
        assertEquals(32, self.options.get_int("Foo", 5))

    # ... and so on for all the tests

class ToolOptions:
    def __init__(self, name):
        self.name = name
        self.options = {}

    def set_int(self, option_name, value):
        if not option_name in self.options:
            self.options[option_name] = {"value": None}
        self.options[option_name]["value"] = value

    def get_int(self, option_name, default_value=None):
        return self.options.get(option_name, {}).get("value", default_value)

    # ... and so on for all the methods
