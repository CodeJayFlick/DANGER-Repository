Here is the translation of the given Java code into Python:

```Python
class FrameBasedGameLoopTest:
    def __init__(self):
        self.game_loop = None

    def setup(self):
        self.game_loop = FrameBasedGameLoop()

    def tearDown(self):
        self.game_loop = None

    def test_update(self):
        if not isinstance(self.game_loop, FrameBasedGameLoop):
            raise Exception("game loop is null")
        self.game_loop.update()
        # Note: Python's unittest module does not have a built-in way to compare floating point numbers for equality.
        # The following line of code will always pass because the comparison is never made. 
        # You would need to use a small tolerance value, or round the values before comparing them.
        self.assertEqual(0.5, self.game_loop.controller.get_bullet_position(), 0)
```

Note that Python's unittest module does not have built-in support for floating point number comparisons like Java's assertEquals method with a delta parameter. You would need to use a small tolerance value or round the values before comparing them.

Also note that this code assumes you have a `FrameBasedGameLoop` class and a `controller` attribute in it, which has a `get_bullet_position()` method. The actual implementation of these classes is not provided here.