Here is the translation of the Java code to Python:
```
# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class Product:
    def __init__(self):
        self._title = None
        self._product_inventories = None

    @property
    def title(self):
        return self._title

    @title.setter
    def title(self, value):
        self._title = value

    @property
    def product_inventories(self):
        return self._product_inventories

    @product_inventories.setter
    def product_inventories(self, value):
        self._product_inventories = value
```
Note that I've used Python's built-in `__init__` method to initialize the instance variables, and property decorators (`@property`) to implement getter and setter methods. This is equivalent to Java's getters and setters using Lombok annotations.