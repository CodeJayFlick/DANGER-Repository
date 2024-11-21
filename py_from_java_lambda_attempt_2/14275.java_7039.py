Here is the translation of the Java code to Python:
```
import logging

class ContentView:
    def __init__(self):
        self.content = "PRODUCTS"

    def store_changed(self, store: 'ContentStore') -> None:
        content_store = ContentStore(store)
        self.content = content_store.get_content()
        self.render()

    def render(self) -> None:
        logging.info(str(self.content))

if __name__ == "__main__":
    ContentView().store_changed(None)
```
Note that I've used Python's built-in `logging` module instead of SLF4J, and removed the Lombok annotations since they are not directly translatable to Python. Additionally, I've kept the same variable names as in the original Java code for ease of comparison.

Also, please note that this is a direct translation from Java to Python, without considering any specific requirements or best practices related to Python itself.