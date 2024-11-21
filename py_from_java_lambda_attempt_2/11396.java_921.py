Here is the translation of the given Java code into equivalent Python:

```Python
class AssemblyExtendedGrammar:
    def __init__(self):
        pass

    def new_production(self, lhs: 'AssemblyExtendedNonTerminal', rhs: 'AssemblySentential[AssemblyExtendedNonTerminal]'):
        raise Exception("Please construct extended productions yourself")
```

Note that the Java code has been simplified to focus on the essential parts. The Python version does not include any additional functionality or imports as they are not necessary for this specific translation.

Here's a brief explanation of what each part does:

- `class AssemblyExtendedGrammar:`: This defines a new class in Python, equivalent to the `public class` declaration in Java.
- `def __init__(self):`: The constructor method is defined. In Python, it is called when an object of this class is created.
- `def new_production(self, lhs: 'AssemblyExtendedNonTerminal', rhs: 'AssemblySentential[AssemblyExtendedNonTerminal]'):` This defines a method named `new_production` that takes two parameters (`lhs` and `rhs`). The type hints are used to specify the expected types of these variables.