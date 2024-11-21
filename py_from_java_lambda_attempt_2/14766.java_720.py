Here is the translation of the Java code to Python:

```Python
class App:
    def main(self):
        ivory_tower = IvoryTower()
        proxy = WizardTowerProxy(ivory_tower)
        
        for i in range(5):  # enter 5 wizards
            wizard_name = f"{'Red' if i == 0 else 'White' if i == 1 else 'Black' if i == 2 else 'Green' if i == 3 else 'Brown'} wizard"
            proxy.enter(Wizard(wizard_name))

if __name__ == "__main__":
    App().main()
```

Note that Python does not have a direct equivalent to Java's `package` statement, so I omitted it. Also, the `var` keyword is used in Java for variable declaration but Python uses no such keyword and automatically infers the type of variables based on their assignment.

The code assumes you have defined classes `IvoryTower`, `WizardTowerProxy`, `Wizard`. If these are not already defined in your program, they would need to be implemented.