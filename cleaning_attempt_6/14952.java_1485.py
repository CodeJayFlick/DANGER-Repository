# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class SingletonTest:
    def __init__(self, instance_method):
        self.instance_method = instance_method

class EnumIvoryTowerTest(SingletonTest):
    # Date: 12/29/15 - 19:20 PM.
    # @author Jeroen Meulemeester
    def __init__(self):
        super().__init__(lambda: EnumIvoryTower.INSTANCE)

# No need to define the Singleton class as it's not provided in the given Java code.

class EnumIvoryTower:
    INSTANCE = None

    def __new__(cls):
        if cls.INSTANCE is None:
            cls.INSTANCE = object.__new__(cls)
        return cls.INSTANCE
