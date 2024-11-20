class ExpressionResults:
    eExpressionCompleted = ("eExpressionCompleted", 0)
    eExpressionSetupError = "eExpressionSetupError"
    eExpressionParseError = "eExpressionParseError"
    eExpressionDiscarded = "eExpressionDiscarded"
    eExpressionInterrupted = "eExpressionInterrupted"
    eExpressionHitBreakpoint = "eExpressionHitBreakpoint"
    eExpressionTimedOut = "eExpressionTimedOut"
    eExpressionResultUnavailable = "eExpressionResultUnavailable"
    eExpressionStoppedForDebug = "eExpressionStoppedForDebug"
    eExpressionThreadVanished = "eExpressionThreadVanished"

    def __init__(self, swig_name):
        self.swig_name = swig_name
        ExpressionResults.next_value += 1

    @classmethod
    def from_swig(cls, swig_value):
        if 0 <= swig_value < len(ExpressionResults.swig_values) and \
           ExpressionResults.swig_values[swig_value][1] == swig_value:
            return ExpressionResults.swig_values[swig_value]
        for i in range(len(ExpressionResults.swig_values)):
            if ExpressionResults.swig_values[i][1] == swig_value:
                return ExpressionResults.swig_values[i]
        raise ValueError(f"No enum {cls.__name__} with value {swig_value}")

    @classmethod
    def from_swig_name(cls, swig_name):
        for i in range(len(ExpressionResults.swig_values)):
            if ExpressionResults.swig_values[i][0] == swig_name:
                return ExpressionResults.from_swig(i)
        raise ValueError(f"No enum {cls.__name__} with name '{swig_name}'")

    @classmethod
    def from_swig_value(cls, swig_value):
        for i in range(len(ExpressionResults.swig_values)):
            if ExpressionResults.swig_values[i][1] == swig_value:
                return ExpressionResults.from_swig(i)
        raise ValueError(f"No enum {cls.__name__} with value {swig_value}")

    @classmethod
    def from_name(cls, name):
        for i in range(len(ExpressionResults.swig_values)):
            if ExpressionResults.swig_values[i][0] == name:
                return ExpressionResults.from_swig(i)
        raise ValueError(f"No enum {cls.__name__} with name '{name}'")

ExpressionResults.next_value = 1
ExpressionResults.swig_values = [getattr(ExpressionResults, f"e{key}") for key in ["ExpressionCompleted", "SetupError", "ParseError", "Discarded", "Interrupted", "HitBreakpoint", "TimedOut", "ResultUnavailable", "StoppedForDebug", "ThreadVanished"]]
