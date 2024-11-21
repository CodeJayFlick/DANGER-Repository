from typing import List

class FGLayoutFinder:
    def find_layouts(self) -> List[object]:
        pass  # Implement this method in your subclass


# Example usage:
class MyFGLayoutFinder(FGLayoutFinder):
    def find_layouts(self) -> List[object]:
        return [1, "hello", {"a": 2}, (3, 4)]  # Replace with actual implementation

my_finder = MyFGLayoutFinder()
print(my_finder.find_layouts())  # Output: [<class 'int'>, <class 'str'>, {'a': 2}, (<class 'int'>, <class 'int'>)]
