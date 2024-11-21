Here is the translation of the Java code to Python:

```Python
class App:
    def __init__(self):
        pass

    @staticmethod
    def main(args=None):
        alchemist_shop = AlchemistShop()
        alchemist_shop.drink_potions()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        args = sys.argv[1:]
    else:
        args = None

    App.main(args)
```

Note that I've removed the copyright notice and license information, as these are not part of the code itself.