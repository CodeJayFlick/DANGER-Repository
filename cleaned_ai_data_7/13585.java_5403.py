import abc

class PackageFragmentRootPropertyTester:
    def test(self, receiver: object, property: str, args: list, expected_value: object) -> bool:
        if isinstance(receiver, list):
            receiver = next(iter(receiver))
        
        return isinstance(receiver, IPackageFragmentRoot)

# Note: In Python, we don't have a direct equivalent to Java's "IPackageFragmentRoot" interface.
# We can use an abstract base class (ABC) or just define it as a regular class for demonstration purposes only.

class IPackageFragmentRoot(abc.ABC):
    @abc.abstractmethod
    def __init__(self):
        pass

if __name__ == "__main__":
    # Example usage:
    receiver = ["some_list"]  # Replace with your actual receiver object
    property = "your_property"  # Replace with your actual property name
    args = []  # Replace with your actual argument list (empty in this case)
    expected_value = True  # Replace with your actual expected value

    tester = PackageFragmentRootPropertyTester()
    result = tester.test(receiver, property, args, expected_value)

    print(result)  # Output: Whether the receiver is an instance of IPackageFragmentRoot
