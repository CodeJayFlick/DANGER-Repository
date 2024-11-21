class ExprFunctionCall:
    def __init__(self, function):
        self.function = function

    def get(self, e):
        return_value = self.function.execute(e)
        self.function.reset_return_value()
        return return_value

    def is_single(self):
        return self.function.is_single()

    def get_return_type(self):
        type_ = self.function.get_return_type()
        assert type_ is not None
        return type_

    def __str__(self, e=None, debug=False):
        if e and debug:
            return f"{e} {self.function.__str__(e, debug)}"
        else:
            return str(self.function)

class FunctionReference:
    pass

# Note: The following classes are not implemented in the given Java code
class SimpleExpression:
    def __init__(self):
        pass

class Kleenean:
    pass

if __name__ == "__main__":
    # Example usage of ExprFunctionCall and its methods
    function = FunctionReference()  # Implement this class to use it with ExprFunctionCall
    expr_function_call = ExprFunctionCall(function)
    
    event = "SomeEvent"  # Replace with actual Event object
    
    result1 = expr_function_call.get(event)  # Call the get method
    print(result1)

    is_single_result = expr_function_call.is_single()  # Call the is_single method
    print(is_single_result)

    return_type = expr_function_call.get_return_type()  # Call the get_return_type method
    print(return_type)
