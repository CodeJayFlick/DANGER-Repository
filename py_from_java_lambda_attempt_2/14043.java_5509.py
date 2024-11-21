Here is the equivalent Python code:

```Python
import os
from typing import List

class DataFetcher:
    def __init__(self):
        self.filename = "world.txt"
        self.last_fetched = -1

    def is_dirty(self) -> bool:
        if self.last_fetched != os.path.getmtime(self.filename):
            self.last_fetched = os.path.getmtime(self.filename)
            return True
        return False

    def fetch(self) -> List[str]:
        try:
            with open(self.filename, 'r') as file:
                lines = [line.strip() for line in file.readlines()]
                return lines
        except Exception as e:
            print(f"Error: {e}")
            return []

if __name__ == "__main__":
    data_fetcher = DataFetcher()
    if data_fetcher.is_dirty():
        print("world.txt is dirty! Re-fetching file content...")
    else:
        print("No need to re-fetch, world.txt is up-to-date.")
```

Please note that Python does not have a direct equivalent of Java's `@Slf4j` annotation. The logging functionality in the original code has been removed for simplicity and focus on translating the rest of the code into Python.