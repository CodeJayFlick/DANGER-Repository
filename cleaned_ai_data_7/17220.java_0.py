import logging

class FunctionOperator:
    def __init__(self, filter_type):
        self.filter_type = filter_type

    @property
    def logger(self):
        return logging.getLogger(__name__)

    def reverse_func(self):
        # Implemented by subclass
        pass

    def add_child_operator(self, op):
        self.logger.error("Cannot add child to leaf FilterOperator, now it's FunctionOperator")
        return False


if __name__ == "__main__":
    filter_type = "some_filter_type"
    function_operator = FunctionOperator(filter_type)
    # Use the `function_operator` object
