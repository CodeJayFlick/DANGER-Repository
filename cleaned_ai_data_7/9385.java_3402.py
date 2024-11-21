class CustomFavoritesView:
    def __init__(self, help_set: 'HelpSet', name: str, label: str, locale: 'Locale', params: dict):
        super().__init__(help_set, name, label, locale, params)

    def create_navigator(self, model) -> Component:
        return CustomHelpFavoritesNavigator(self, model)


class CustomHelpFavoritesNavigator(JComponent):
    def __init__(self, view: 'CustomFavoritesView', model: 'HelpModel'):
        super().__init__()
        self.view = view
        self.model = model

    def set_ui(self, ui) -> None:
        super().setUI(CustomFavoritesNavigatorUI(self))


class CustomFavoritesNavigatorUI(BasicFavoritesNavigatorUI):
    def __init__(self, b: JHelpFavoritesNavigator):
        super().__init__(b)

    def install_ui(self, c: Component) -> None:
        super().installUI(c)
        tree = self.tree
        tree.addKeyListener(KeyAdapter())
        for e in (KeyEvent.VK_DELETE, KeyEvent.VK_BACK_SPACE):
            if e.getKeyCode() == e:
                remove_action.action_performed(None)

        model = self.favorites.get_model()
        title_listener = PropertyChangeListener()
        last_id_event = None

    def uninstall_ui(self, c: Component) -> None:
        super().uninstallUI(c)
        model = self.favorites.get_model()
        if model is not None:
            model.remove_property_change_listener(title_listener)


class CustomFavoritesCellRenderer(BasicFavoritesCellRenderer):
    def __init__(self, help_model: 'HelpModel'):
        super().__init__()
        self.help_model = help_model

    def get_tree_cell_renderer_component(self, tree: JTree, value: object, selected: bool,
                                          expanded: bool, leaf: bool, row: int, is_focused: bool) -> Component:
        renderer = super().get_tree_cell_renderer_component(tree, value, selected, expanded, leaf, row, is_focused)
        o = (DefaultMutableTreeNode(value)).user_object
        item = FavoritesItem(o)

        if item is None:
            return renderer

        help_set = self.help_model.get_help_set()
        combined_map = help_set.get_combined_map()

        url = get_url(item, help_set, combined_map)
        if url is None:
            # should only happen if the user has old favorites; trust the old name
            return renderer

        text = url.file
        index = text.rfind('/')
        if index != -1:
            # we want just the filename
            text = text[index + 1:]

        ref = url.ref
        if ref is not None:
            text += '#' + ref

        renderer.text = item.name + ' - ' + text

        return renderer


def get_url(item: FavoritesItem, help_set: 'HelpSet', combined_map: dict) -> URL:
    target = item.target
    if target is None:
        # use the url of the item
        return item.url

    new_id = ID.create(target, help_set)
    try:
        return combined_map[url_from_id(new_id)]
    except MalformedURLException as e:
        Msg.error(self, 'Unexpected Exception', e)

    return None


class FavoritesItem:
    def __init__(self, target: str):
        self.target = target
