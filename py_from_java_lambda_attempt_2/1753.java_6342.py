Here is the equivalent Python code:

```Python
class ExpressionEvaluationPhase:
    _values = ['eExpressionEvaluationParse', 'eExpressionEvaluationIRGen', 'eExpressionEvaluationExecution', 'eExpressionEvaluationComplete']
    _next_value = 0

    def __init__(self, name):
        self.name = name
        global _next_value
        self.value = _next_value
        _next_value += 1

    @classmethod
    def swig_to_enum(cls, value):
        if isinstance(value, int) and 0 <= value < len(cls._values):
            return cls._values[value]
        for v in cls._values:
            if getattr(v, 'value') == value:
                return v
        raise ValueError(f"No enum {cls.__name__} with value {value}")

    def __str__(self):
        return self.name

    @property
    def swig_value(self):
        return self.value


ExpressionEvaluationPhase.e_expression_evaluation_parse = ExpressionEvaluationPhase('eExpressionEvaluationParse', lldbJNI.eExpressionEvaluationParse_get())
ExpressionEvaluationPhase.e_expression_evaluation_ir_gen = ExpressionEvaluationPhase('eExpressionEvaluationIRGen')
ExpressionEvaluationPhase.e_expression_evaluation_execution = ExpressionEvaluationPhase('eExpressionEvaluationExecution')
ExpressionEvaluationPhase.e_expression_evaluation_complete = ExpressionEvaluationPhase('eExpressionEvaluationComplete')

```

Note that I had to make some assumptions about the `lldbJNI` module and its methods, as they are not defined in this code.