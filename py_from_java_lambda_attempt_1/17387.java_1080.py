Here's your Java code translated into Python:

```Python
class MaxTimeDescAggrResult:
    def __init__(self):
        self.has_candidate_result = False

    def update_result_from_statistics(self, statistics):
        if self.has_final_result():
            return
        super().update_result_from_statistics(statistics)

    def has_final_result(self):
        return self.has_candidate_result


class MaxTimeAggrResult:
    pass  # This class is not implemented in the provided Java code.