Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class OrcKing:
    def __init__(self):
        self.build_chain()

    def build_chain(self):
        self.chain = OrcCommander(OrcOfficer(OrcSoldier(None)))

    def make_request(self, req: 'Request'):
        self.chain.handle_request(req)

# No equivalent to Java's package declaration in Python
```
Note that I've removed the `package` declaration at the top, as it is not necessary or meaningful in a Python context. Additionally, I've used type hints for the `make_request` method and its argument, but this is purely optional and does not affect the functionality of the code.

The rest of the translation was straightforward: Java's classes become Python classes, methods become functions (with slightly different syntax), and variables are assigned using the `=` operator.