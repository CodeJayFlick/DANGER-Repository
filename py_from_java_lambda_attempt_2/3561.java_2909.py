Here is the translation of the Java code into Python:

```Python
class CompositeEditorActionManager:
    def __init__(self, provider):
        self.provider = provider
        self.data_type_mgr_service = None
        self.adapter = DataTypeManagerChangeListenerAdapter()
        
        if self.data_type_mgr_service is not None:
            favorites = self.data_type_mgr_service.get_favorites()
            self.set_favorites_actions(favorites)
            self.data_type_mgr_service.add_data_type_manager_change_listener(self.adapter)

    def dispose(self):
        if self.data_type_mgr_service is not None:
            self.data_type_mgr_service.remove_data_type_manager_change_listener(self.adapter)
        
        self.listeners.clear()
        self.editor_actions.clear()
        self.favorites_actions.clear()
        self.cycle_group_actions.clear()

    def add_editor_action_listener(self, listener):
        self.listeners.append(listener)

    def remove_editor_action_listener(self, listener):
        if listener in self.listeners:
            self.listeners.remove(listener)

    def get_editor_actions(self):
        return list(self.editor_actions)

    def get_favorites_actions(self):
        return list(self.favorites_actions)

    def get_cycle_group_actions(self):
        return list(self.cycle_group_actions)

    def get_all_actions(self):
        all_actions = []
        for action in self.get_editor_actions():
            all_actions.append(action)
        
        for action in self.get_favorites_actions():
            all_actions.append(action)
        
        for action in self.get_cycle_group_actions():
            all_actions.append(action)
        
        return all_actions

    def get_named_action(self, name):
        for action in self.editor_actions:
            if action.name == name:
                return action
        
        for action in self.favorites_actions:
            if action.name == name:
                return action
        
        for action in self.cycle_group_actions:
            if action.name == name:
                return action
        
        return None

    def set_editor_actions(self, actions):
        self.editor_actions.clear()
        
        for action in actions:
            self.editor_actions.append(action)

    def set_favorites_actions(self, favorites):
        self.favorites_actions.clear()

        for data_type in favorites:
            action = FavoritesAction(self.provider, data_type)
            self.favorites_actions.append(action)
        
        self.notify_actions_added(self.favorites_actions)

    def clear_favorites_actions(self):
        self.notify_actions_removed(self.favorites_actions)
        self.favorites_actions.clear()

    def set_cycle_group_actions(self):
        self.cycle_group_actions.clear()
        
        for group in CycleGroup.ALL_CYCLE_GROUPS:
            action = CycleGroupAction(self.provider, group)
            self.cycle_group_actions.append(action)
        
        self.notify_actions_added(self.cycle_group_actions)

    def clear_cycle_group_actions(self):
        self.notify_actions_removed(self.cycle_group_actions)
        self.cycle_group_actions.clear()

    def notify_actions_added(self, actions):
        if len(actions) <= 0:
            return
        
        for listener in self.listeners:
            listener.actions_added(list(actions))

    def notify_actions_removed(self, actions):
        if len(actions) <= 0:
            return
        
        for listener in self.listeners:
            listener.actions_removed(list(actions))
```

Please note that this is a direct translation of the Java code into Python. The equivalent classes and methods are used to represent similar concepts between both languages.