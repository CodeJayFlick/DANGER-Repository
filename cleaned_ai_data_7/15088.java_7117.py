# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import typing as t

class Throttler:
    """An interface for defining the structure of different types of throttling ways."""

    def start(self):
        pass


if __name__ == "__main__":
    print("Throttler Interface Translated to Python")
