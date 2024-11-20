Here is the translation of the Java code to Python:
```
import http.client as client

class NessieApiClient:
    def __init__(self, config: 'HttpConfigApi', tree: 'HttpTreeApi', contents: 'HttpContentsApi'):
        self.config = config
        self.tree = tree
        self.contents = contents

    @property
    def tree_api(self):
        return self.tree

    @property
    def contents_api(self):
        return self.contents

    @property
    def config_api(self):
        return self.config

    def close(self):
        pass  # equivalent to Java's `@Override public void close() {}`
```
Note that I used Python's type hinting feature (`'HttpConfigApi', 'HttpTreeApi', etc.) to indicate the expected types of the `config`, `tree`, and `contents` attributes. This is not enforced at runtime, but can be useful for documentation purposes.

Also, in Python, we don't need an explicit `close()` method implementation since it's a no-op (does nothing).