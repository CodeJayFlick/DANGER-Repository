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
