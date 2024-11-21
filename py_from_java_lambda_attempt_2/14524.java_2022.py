Here is the translation of the Java code to Python:

```
# The MIT License
# Copyright © 2014-2021 Ilkka Seppälä

class PartyMember:
    """Interface for party members interacting with `Party`."""

    def joined_party(self, party):
        pass

    def party_action(self, action):
        pass

    def act(self, action):
        pass
```

Note that in Python, we don't have a direct equivalent to Java's interfaces. Instead, we use abstract base classes (ABCs) or protocols (in the context of type hints). Since you didn't specify any particular implementation details, I've kept the `PartyMember` class as an abstract placeholder with empty method implementations.