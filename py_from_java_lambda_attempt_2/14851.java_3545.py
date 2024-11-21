Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import abc

class OrderService(metaclass=abc.ABCMeta):
    def __init__(self, service_discovery_service):
        pass

    @property
    def name(self):
        return "Init an order"
```
Note that I did not translate the Java-specific concepts like `package`, `public class`, `extends Service`, etc. Python has its own way of organizing code and defining classes, so I focused on translating the relevant parts.

Here's a brief explanation:

* The license information is left as-is.
* In Python, we don't need to specify a package or import statements for Java-style packages.
* The `OrderService` class is defined using the `class` keyword. Since it doesn't inherit from any specific parent class (like `java.lang.Object`), I used the `metaclass=abc.ABCMeta` syntax to indicate that this is an abstract base class (ABC).
* The constructor (`__init__`) takes a single argument, `service_discovery_service`, which is not explicitly used in this example.
* The `name` property is defined using Python's built-in property decorator. This allows us to define a read-only attribute on the class.

Keep in mind that this translation is just an approximation of the original Java code and may require additional modifications or context-specific changes depending on how you plan to use it in your Python project.