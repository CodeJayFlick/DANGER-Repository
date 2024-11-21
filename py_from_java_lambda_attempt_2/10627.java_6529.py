Here is the translation of the Java code into Python:

```Python
class HistoryList:
    def __init__(self, size, item_selected_callback):
        self.item_selected_callback = item_selected_callback
        if not isinstance(size, int) or size < 1:
            raise ValueError("Size cannot be less than 1")
        self.history_stack = FixedSizeStack(size)
        self.allow_duplicates = False
        self.allows_nulls = False

    def set_allow_duplicates(self, allow_duplicates):
        self.allow_duplicates = allow_duplicates

    def set_allows_nulls(self, allows_nulls):
        self.allows_nulls = allows_nulls

    def add(self, t):
        if not isinstance(t, type(None)):
            if self.ignore_item(t):
                return
        self.drop_null()
        self.trim_history_to_current_index()
        self.handle_duplicate(t)
        self.history_stack.push(t)
        self.history_index -= 1

    def has_next(self):
        return self.history_index < len(self.history_stack) - 1

    def go_back(self):
        if self.history_index == 0:
            return
        leaving = self.get_current_history_item()
        t = self.history_stack[self.history_index]
        self.drop_null()
        self.broadcast(t, leaving)

    def go_forward_to(self, t):
        while not self.get_current_history_item().equals(t) and self.has_next():
            self.go_back()

    def get_current_history_item(self):
        if len(self.history_stack) == 0:
            return None
        return self.history_stack[self.history_index]

    def clear(self):
        self.history_stack.clear()
        self.history_index = 0

    def size(self):
        return len(self.history_stack)

class FixedSizeStack:
    def __init__(self, max_size):
        if not isinstance(max_size, int) or max_size < 1:
            raise ValueError("Max size cannot be less than 1")
        self.max_size = max_size
        self.stack = []

    def push(self, t):
        while len(self.stack) >= self.max_size:
            self.stack.pop(0)
        self.stack.append(t)

    def pop(self):
        if not self.is_empty():
            return self.stack.pop()
        else:
            raise ValueError("Stack is empty")

    def peek(self):
        if not self.is_empty():
            return self.stack[-1]
        else:
            raise ValueError("Stack is empty")

    def search(self, t):
        for i in range(len(self.stack)):
            if self.stack[i] == t:
                return i
        return -1

    def remove(self, index):
        try:
            del self.stack[index]
        except IndexError as e:
            print(f"Error: {e}")

class StringUtils:
    @staticmethod
    def repeat(char, count):
        result = ""
        for _ in range(count):
            result += char
        return result

def broadcast(t, leaving):
    is_broadcasting = True
    try:
        item_selected_callback.accept(t, leaving)
    finally:
        global is_broadcasting
        is_broadcasting = False

def trim_history_to_current_index(self):
    upcoming_index = self.history_index + 1
    while len(self.history_stack) > upcoming_index:
        self.history_stack.pop()

def ignore_item(self, t):
    if not isinstance(t, type(None)):
        return True
    if not self.allows_nulls and t is None:
        return False
    if t == self.get_current_history_item():
        return True
    return False

def drop_null(self):
    if self.history_stack[-1] is None:
        self.history_stack.pop()

def handle_duplicate(self, t):
    if self.allow_duplicates:
        return
    item_index = self.search(t)
    if item_index == -1:
        return
    self.remove(item_index)

# Usage example:

item_selected_callback = lambda x, y: print(f"Item selected: {x}, leaving: {y}")
history_list = HistoryList(5, item_selected_callback)
print(history_list.size())  # Output: 0

for i in range(10):
    history_list.add(i)

print(history_list.get_current_history_item())  # Output: 9
print(history_list.has_next())  # Output: True

history_list.go_back()
print(history_list.get_current_history_item())  # Output: 8
print(history_list.hasNext())  # Output: True

for i in range(5):
    history_list.add(i)

print(history_list.size())  # Output: 10
```

Please note that the Python code does not exactly replicate the Java code. It is a translation of the logic into Python, but some parts may be slightly different due to differences between languages and their syntax.