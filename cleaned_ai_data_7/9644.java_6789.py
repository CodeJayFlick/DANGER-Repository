class MultitermEvaluationMode:
    AND = ("Object must match all filter terms",)
    OR = ("Object must match at least one filter term",)

    def __init__(self, descr):
        self.descr = descr

    @property
    def description(self):
        return self.descr
