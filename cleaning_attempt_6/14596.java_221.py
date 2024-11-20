# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import json

class HomePageViewModel:
    def __init__(self):
        self.simple_objects = None

    @property
    def title(self):
        return f"{len(self.get_objects())} objects"

    @property
    def get_objects(self):
        if not hasattr(self, '_get_objects'):
            self._get_objects = []
        return self._get_objects

# Note: The equivalent of Java's `@Inject` annotation is not needed in Python,
# as dependency injection can be achieved through other means (e.g., using a library like injector).
