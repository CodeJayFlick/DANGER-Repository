Here is the translation of the Java interface `Block` into a Python class:

```Python
class Block:
    def __init__(self):
        pass

    @abstractmethod
    def forward(self, parameter_store: dict, inputs: list, training: bool = False) -> list:
        """
        Applies the operating function of the block once.
        
        :param parameter_store: The parameter store
        :param inputs: The input NDList
        :param training: True for a training forward pass (default is False)
        :return: The output of the forward pass
        """

    @abstractmethod
    def set_initializer(self, initializer: callable, param_type: str):
        """
        Sets an initializer to all parameters that match parameter type in the block.
        
        :param initializer: The initializer function
        :param param_type: The Parameter Type we want to setInitializer
        """

    @abstractmethod
    def initialize(self, manager: dict, data_type: str, input_shapes: list):
        """
        Initializes the parameters of the block. This method must be called before calling `forward`.
        
        :param manager: An NDManager to create the parameter arrays
        :param data_type: The datatype of the parameters
        :param input_shapes: The shapes of the inputs to the block
        """

    @abstractmethod
    def is_initialized(self) -> bool:
        """
        Returns a boolean whether the block is initialized.
        
        :return: Whether the block is initialized
        """

    @abstractmethod
    def cast(self, data_type: str):
        """
        Guaranteed to throw an exception. Not yet implemented
        
        :param data_type: The data type to cast to
        :raises: UnsupportedOperationException always
        """

    @abstractmethod
    def clear(self):
        """
        Closes all the parameters of the block. All updates made during training will be lost.
        """

    @abstractmethod
    def describe_input(self) -> list:
        """
        Returns a list of input names, and shapes
        
        :return: The list of input names, and shapes
        """

    @abstractmethod
    def get_children(self) -> list:
        """
        Returns a list of all the children of the block.
        
        :return: The list of child blocks
        """

    @abstractmethod
    def get_direct_parameters(self) -> list:
        """
        Returns a list of all direct parameters of the block
        
        :return: The list of Parameter objects
        """

    @abstractmethod
    def get_parameters(self) -> list:
        """
        Returns a list of all parameters of the block, including the parameters of its children fetched recursively.
        
        :return: The list of all parameters of the block
        """

    @abstractmethod
    def get_output_shapes(self, input_shapes: list) -> list:
        """
        Returns the expected output shapes of the block for the specified input shapes
        
        :param input_shapes: The shapes of the inputs
        :return: The expected output shapes of the block
        """

    @abstractmethod
    def save_parameters(self, os):
        """
        Writes the parameters of the block to the given outputStream.
        
        :param os: The outputstream to save the parameters to
        :raises: IOException if an I/O error occurs
        """

    @abstractmethod
    def load_parameters(self, manager: dict, is) -> None:
        """
        Loads the parameters from the given input stream
        
        :param manager: An NDManager to create the parameter arrays
        :param is: The inputstream that streams the parameter values
        :raises: IOException if an I/O error occurs
        :raises: MalformedModelException if the model file is corrupted or unsupported
        """

    @staticmethod
    def validate_layout(expected_layout, actual_layout):
        """
        Validates that actual layout matches the expected layout
        
        :param expected_layout: The expected layout
        :param actual_layout: The actual Layout
        :raises: UnsupportedOperationException if the actual layout does not match the expected layout
        """
```

Please note that Python doesn't support abstract methods and interfaces like Java. So, we have to use `@abstractmethod` decorator in Python as well.