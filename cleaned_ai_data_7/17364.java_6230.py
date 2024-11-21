import logging

class LogicalChecker:
    def __init__(self):
        pass  # private constructor

    @staticmethod
    def check(operator: 'Operator') -> None:
        if isinstance(operator, QueryOperator):
            operator.check()
        elif isinstance(operator, SelectIntoOperator):
            operator.check()

class Operator:
    pass  # abstract class or interface in Python


class QueryOperator(Operator):
    def __init__(self):
        pass

    def check(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")


class SelectIntoOperator(Operator):
    def __init__(self):
        pass

    def check(self) -> None:
        raise NotImplementedError("Subclasses must implement this method")
