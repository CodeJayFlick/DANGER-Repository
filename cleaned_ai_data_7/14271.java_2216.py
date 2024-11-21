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
