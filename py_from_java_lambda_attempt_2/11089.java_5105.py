Here is the translation of the Java code to Python:
```
import logging

class ArrowDownSelectionAction:
    def __init__(self, event_listener):
        self.event_listener = event_listener

    def perform_action(self):
        # Now fire off an event to tell any subscribers to perform the increment.
        event_type = "increment_and_add_selection"
        event_data = 1
        self.event_listener.send(event_type, event_data)
```
Note that I did not include a `__main__` block or any other Python-specific constructs. This is simply a direct translation of the Java code to Python.

Here's a brief explanation of the changes:

* In Python, we don't need explicit type declarations for variables.
* The `public` access modifier has no equivalent in Python; I removed it.
* The `@Override` annotation is not necessary in Python, as method overriding works differently than in Java. Instead, I simply defined a new method called `perform_action`.
* In the constructor (`__init__`), we assign the `event_listener` attribute to the passed-in value.
* In the `actionPerformed` method (now renamed to `perform_action`), we create an event object with type `"increment_and_add_selection"` and data `1`, then call the `send` method on the `event_listener`.

This Python code is equivalent in functionality to the original Java code.