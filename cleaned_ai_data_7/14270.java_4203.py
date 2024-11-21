class App:
    def __init__(self):
        pass

    @staticmethod
    def main(args=None):
        # initialize and wire the system
        menu_store = MenuStore()
        Dispatcher().register_store(menu_store)
        content_store = ContentStore()
        Dispatcher().register_store(content_store)
        menu_view = MenuView()
        menu_store.register_view(menu_view)
        content_view = ContentView()
        content_store.register_view(content_view)

        # render initial view
        menu_view.render()
        content_view.render()

        # user clicks another menu item
        # this triggers action dispatching and eventually causes views to render with new content
        menu_view.item_clicked(MenuItem.COMPANY)


class MenuItem:
    COMPANY = "COMPANY"


class Dispatcher:
    @staticmethod
    def get_instance():
        return Dispatcher

    @classmethod
    def register_store(cls, store):
        pass


class MenuStore:
    def __init__(self):
        self.views = []

    def register_view(self, view):
        self.views.append(view)

    def render_views(self):
        for view in self.views:
            view.render()


class ContentView:
    def __init__(self):
        pass

    def render(self):
        print("Content View rendered")


class MenuView:
    def __init__(self):
        pass

    def item_clicked(self, menu_item):
        # Dispatch action
        pass

    def render(self):
        print("Menu View rendered")
