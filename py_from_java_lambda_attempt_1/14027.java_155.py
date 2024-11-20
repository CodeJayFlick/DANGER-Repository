Here is the translation of the Java code to Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import inject

class SimpleWizard:
    def __init__(self):
        pass

    def smoke(self):
        print("Simple Wizard smokes")

class AdvancedWizard(SimpleWizard):
    def __init__(self, tobacco):
        self.tobacco = tobacco

    def smoke(self):
        self.tobacco.smoke()

class AdvancedSorceress:
    def __init__(self):
        pass

    def set_tobacco(self, tobacco):
        self.tobacco = tobacco

    def smoke(self):
        self.tobacco.smoke()

class SecondBreakfastTobacco:
    def smoke(self):
        print("Second Breakfast Tobacco smokes")

def main():
    simple_wizard = SimpleWizard()
    simple_wizard.smoke()

    advanced_wizard = AdvancedWizard(SecondBreakfastTobacco())
    advanced_wizard.smoke()

    advanced_sorceress = AdvancedSorceress()
    advanced_sorceress.set_tobacco(SecondBreakfastTobacco())
    advanced_sorceress.smoke()

    injector = inject.Injector()
    guice_wizard = injector.inject_modules([inject.Module(lambda binder: binder.bind("tobacco", to=SecondBreakfastTobacco()))]).get_instance(GuiceWizard)
    guice_wizard.smoke()

if __name__ == "__main__":
    main()
```

Please note that Python does not have a direct equivalent of Java's Guice framework. The above code uses the `inject` library, which is a lightweight dependency injection tool for Python.