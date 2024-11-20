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
