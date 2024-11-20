Here's your Java enum translated into a Python class:

```Python
class VTMarcupItemConsideredStatus:
    UNCONSIDERED = 0
    IGNORE_DONT_KNOW = 1
    IGNORE_DONT_CARE = 2
    REJECT = 3

    def __init__(self, status):
        self.status = status

    @property
    def markup_item_status(self):
        return self.status


# Example usage:
status = VTMarcupItemConsideredStatus.VTMarkupItemConsideredStatus.IGNOR