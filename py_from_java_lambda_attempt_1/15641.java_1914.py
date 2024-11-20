Here is the translation of the Java code into Python:

```Python
class Record:
    def __init__(self, data: 'NDList', labels: 'NDList'):
        self.data = data
        self.labels = labels


def NDList(data):
    return data


# Example usage:
data1 = NDList([1, 2, 3])
labels1 = NDList(['a', 'b', 'c'])
record1 = Record(data1, labels1)

print(record1.data)  # Output: [1, 2, 3]
print(record1.labels)  # Output: ['a', 'b', 'c']
```

Please note that Python does not have direct equivalent of Java's `NDList` class. The above code is a simple translation and may need to be modified based on the actual functionality you want your `Record` class to provide.

Also, in this example, I used type hints for the parameters of the constructor (`__init__`) method, but Python does not enforce these types at runtime like Java would with its static typing.