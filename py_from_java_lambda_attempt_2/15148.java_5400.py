Here is the translation of the given Java code into Python:

```Python
class Statue:
    def __init__(self, id):
        self.id = id
        self.frames = 0
        self.delay = 0

    def update(self):
        if self.frames + 1 == self.delay:
            self.shoot_lightning()
            self.frames = 0
        else:
            self.frames += 1

    def shoot_lightning(self):
        print(f"Statue {self.id} shoots lightning!")
```

Note that Python does not have a direct equivalent to Java's `package` statement. Also, the concept of "logger" is missing in this translation as it seems like an external logging mechanism which may be implemented differently depending on your specific use case.