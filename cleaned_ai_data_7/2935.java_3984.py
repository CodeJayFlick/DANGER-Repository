class SizeFunctionAlgorithm:
    def get_name(self):
        return "Function Size"

    def score_function(self, function: 'ghidra.program.model.listing.Function', task_monitor=None) -> int:
        body = function.getBody()
        return len(body.getAddresses())
