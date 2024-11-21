class GTaskResultInfo:
    def __init__(self, result):
        self.result = result

    def get_result(self):
        return self.result

    def __str__(self):
        if self.result is None:
            return "---- New Transaction ------"
        else:
            return str(self.result)
