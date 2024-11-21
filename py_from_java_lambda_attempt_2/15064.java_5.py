Here is the translation of the Java code to Python:

```Python
class HalflingThief:
    def __init__(self, method):
        self.method = method

    def steal(self):
        print("Stealing...")
        self.method.hit_and_run()
        print("Done stealing...")

    def change_method(self, new_method):
        self.method = new_method


class HitAndRunMethod:
    def hit_and_run(self):
        print("Hitting and running...")


class SubtleMethod:
    def hit_and_run(self):
        print("Stealing subtly...")


def main():
    thief = HalflingThief(HitAndRunMethod())
    thief.steal()
    thief.change_method(SubtleMethod())
    thief.steal()


if __name__ == "__main__":
    main()
```

This Python code defines a `HalflingThief` class that has methods to steal and change the method of stealing. The actual stealing is done by subclasses of `StealingMethod`, which are represented by `HitAndRunMethod` and `SubtleMethod`. In the `main` function, an instance of `HalflingThief` with a `HitAndRunMethod` is created, it steals once using this method, then changes to `SubtleMethod` and steals again.