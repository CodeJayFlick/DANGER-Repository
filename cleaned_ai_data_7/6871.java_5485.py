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
