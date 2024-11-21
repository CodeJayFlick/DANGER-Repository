class IDebugHostEvaluator1:
    IID_IDEBUG_HOST_EVALUATOR = "0FEF9A21-577E-4997-AC7B-1C4883241D99"

    VTIndices1 = {
        'EvaluateExpression': 3,
        'EvaluateExtendedExpression': 4
    }

    def evaluate_expression(self, context, expression, binding_context):
        pass

    def evaluate_extended_expression(self, context, expression, binding_context):
        pass


class HRESULT:
    @staticmethod
    def success():
        return True

    @staticmethod
    def failure():
        return False
