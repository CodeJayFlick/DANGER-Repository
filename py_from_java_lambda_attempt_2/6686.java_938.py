Here is the translation of the Java code into Python:

```Python
class PercentageFilter:
    def __init__(self, percentage):
        if not 0 <= percentage <= 100:
            raise ValueError("Not a valid percentage: {}".format(percentage))
        self.percentage = percentage

    def allows(self, percentage_to_test):
        return percentage_to_test >= self.percentage

    def __str__(self):
        return "Percentage: {}".format(str(self.percentage))

class FunctionBitPatternsGTreeNode:
    pass  # This class is not defined in the original Java code and was left as-is for simplicity.

def main():
    filter = PercentageFilter(50)
    print(filter)  # Output: Percentage: 50.0

if __name__ == "__main__":
    main()
```

Note that I did not translate `FunctionBitPatternsGTreeNode` because it is not defined in the original Java code and was left as-is for simplicity.