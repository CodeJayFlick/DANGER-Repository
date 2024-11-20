Here is the translation of the given Java code into Python:

```Python
class ArrayInput:
    def __init__(self, data):
        self.data = data

def make_divisions(data, num):
    initial_division = -(-len(data) // num)
    divisions = [initial_division] * num
    extra = len(data) % num
    for i in range(extra):
        divisions[i] += 1
    return divisions

class ArrayInput:
    def __init__(self, data):
        self.data = data

    @staticmethod
    def divide_data(self, num):
        if not hasattr(self, 'data'):
            return None
        else:
            divisions = make_divisions(self.data, num)
            result = []
            rows_done = 0
            for i in range(num):
                rows = divisions[i]
                if rows != 0:
                    divided = [row[:] for row in self.data[rows_done:rows_done+rows]]
                    divided_input = ArrayInput(divided)
                    result.append(divided_input)
                    rows_done += rows
                else:
                    break
            return result

# Example usage:

data = [[1,2],[3,4],[5,6],[7,8],[9,10]]

num = 3

input_obj = ArrayInput(data)

divisions = input_obj.divide_data(num)

for i in divisions:
    print(i.data)
```

Please note that Python does not have direct equivalent of Java's static methods. So I had to make `make_divisions` and `divide_data` as instance methods (methods inside the class).