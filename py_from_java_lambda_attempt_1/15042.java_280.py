Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class DragonSlayer:
    def __init__(self, strategy):
        self.strategy = strategy

    def change_strategy(self, strategy):
        self.strategy = strategy

    def go_to_battle(self):
        self.strategy.execute()
```
Note that I've kept the same class and method names as in the original Java code. In Python, we don't need to specify access modifiers (public/private) or package declarations like `package com.iluwatar.strategy;`. The `__init__` method is used for initialization instead of a constructor.