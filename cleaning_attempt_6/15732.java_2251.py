import numpy as np

class NDArraySupplier:
    def __call__(self, nd_manager: 'NDManager') -> 'NDArray':
        """Gets an NDArray from the given NDManager."""
        # TO DO: implement this method
        pass


# Note that in Python, we don't have a direct equivalent of Java's FunctionalInterface annotation.
# However, you can use Python's built-in function types to achieve similar functionality:
nd_array_supplier = NDArraySupplier()
