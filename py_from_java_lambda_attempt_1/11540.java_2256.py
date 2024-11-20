Here is the translation of the given Java code into equivalent Python:

```Python
class TripleSymbol:
    def get_pattern_expression(self):
        pass  # Abstract method in Python, needs implementation in subclass

    def resolve(self, walker: 'ParserWalker', debug: 'SleighDebugLogger') -> None:
        return None  # Return type is None because the function doesn't have a meaningful return value

    def get_fixed_handle(self, hand: 'FixedHandle', walker: 'ParserWalker') -> None:
        pass  # Abstract method in Python, needs implementation in subclass

    def print(self, walker: 'ParserWalker') -> str:
        raise NotImplementedError("Method not implemented")

    def print_list(self, walker: 'ParserWalker', list: list) -> None:
        raise NotImplementedError("Method not implemented")
```

Note that the equivalent of Java's `abstract` keyword in Python is simply defining a method without an implementation. The methods marked as abstract (`getPatternExpression`, `resolve`, and `getFixedHandle`) need to be implemented by any subclass of `TripleSymbol`.