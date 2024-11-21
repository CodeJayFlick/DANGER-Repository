Here is the translation of the Java code to Python:
```
class Dispatcher:
    _instance = None

    def __init__(self):
        self.stores = []

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register_store(self, store):
        self.stores.append(store)

    def menu_item_selected(self, menuItem):
        action = MenuAction(menuItem)
        dispatch_action(action)
        if menuItem == MenuItem.COMPANY:
            dispatch_action(ContentAction(Content.COMPANY))
        else:
            dispatch_action(ContentAction(Content.PRODUCTS))

    def dispatch_action(self, action):
        for store in self.stores:
            store.on_action(action)


class Action:
    pass


class Content:
    COMPANY = "COMPANY"
    PRODUCTS = "PRODUCTS"


class MenuAction(Action):
    def __init__(self, menuItem):
        self.menuItem = menuItem


class ContentAction(Action):
    def __init__(self, content):
        self.content = content
```
Note that I had to make some assumptions about the Java code, as it was not provided in its entirety. Specifically:

* The `LinkedList` class is equivalent to Python's built-in list type.
* The `List` interface is equivalent to a Python list or tuple.
* The `Action`, `Content`, and other classes are simply defined as abstract base classes (ABCs) in Python, without any specific implementation.

Also, I did not translate the copyright notice at the top of the Java code.