Here is the translation of the given Java code into Python:

```Python
class DecompilerConfigurer:
    """A callback interface that will be given a newly created DecompInterface 
       to configure."""

    def __init__(self):
        pass

    def configure(self, decompiler: 'DecompInterface') -> None:
        """
        Configure the given decompiler.

        :param decompiler: The decompiler to configure.
        """

        # Your code here
```

Please note that Python does not have direct equivalent of Java's interface concept. However, we can achieve similar functionality using abstract classes or protocols in Python. In this case, I used a class as it seems like the most suitable option for your problem.