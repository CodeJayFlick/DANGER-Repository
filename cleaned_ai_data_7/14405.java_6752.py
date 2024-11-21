class MultiplyExpressionTest:
    def __init__(self):
        super().__init__("*", lambda: MultiplyExpression())

    @staticmethod
    def expression_provider():
        return [(f, s) for f in range(10) for s in range(10)]

# This is not a direct translation of the Java code. The original Java code was using JUnit and Streams API to test expressions.
