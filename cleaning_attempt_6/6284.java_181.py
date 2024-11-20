class AbstractUnionEditorTest:
    def __init__(self):
        self.union_model = None
        # Editor Actions
        self.apply_action = None
        self.array_action = None
        self.delete_action = None
        self.duplicate_action = None
        self.duplicate_multiple_action = None
        self.edit_component_action = None
        self.edit_field_action = None
        self.move_down_action = None
        self.move_up_action = None
        self.pointer_action = None
        self.show_component_path_action = None
        self.hex_numbers_action = None

    def get_model(self):
        return self.union_model

    def init(self, dt, cat, show_in_hex):
        assert dt.get_category_path() == cat.get_category_path(), "Category path mismatch"
        
        commit = True
        try:
            data_type_manager = cat.data_type_manager()
            if dt.data_type_manager != data_type_manager:
                dt = dt.clone(data_type_manager)
            
            category_path = cat.category_path
            if not dt.category_path == category_path:
                try:
                    dt.set_category_path(category_path)
                except DuplicateNameException as e:
                    commit = False
                    assert False, str(e)

        finally:
            end_transaction(commit)

        union_dt = dt
        run_swing(lambda: install_provider(UnionEditorProvider(self.plugin, union_dt, show_in_hex)))
        self.model = provider.get_model()
        
        get_actions()

    def cleanup(self):
        clear_actions()
        run_swing(provider.dispose)
        self.union_model = None

    def clear_actions(self):
        actions = None
        favorites.clear()
        cycles.clear()
        self.apply_action = None
        self.array_action = None
        self.delete_action = None
        self.duplicate_action = None
        self.duplicate_multiple_action = None
        self.edit_component_action = None
        self.edit_field_action = None
        self.move_down_action = None
        self.move_up_action = None
        self.pointer_action = None
        self.show_component_path_action = None
        self.hex_numbers_action = None

    def get_actions(self):
        actions = provider.get_actions()
        
        for action in actions:
            if isinstance(action, FavoritesAction):
                favorites.add(action)
            elif isinstance(action, CycleGroupAction):
                cycles.add(action)
            elif isinstance(action, ApplyAction):
                self.apply_action = action
            elif isinstance(action, ArrayAction):
                self.array_action = action
            elif isinstance(action, DeleteAction):
                self.delete_action = action
            elif isinstance(action, DuplicateAction):
                self.duplicate_action = action
            elif isinstance(action, DuplicateMultipleAction):
                self.duplicate_multiple_action = action
            elif isinstance(action, EditComponentAction):
                self.edit_component_action = action
            elif isinstance(action, EditFieldAction):
                self.edit_field_action = action
            elif isinstance(action, MoveDownAction):
                self.move_down_action = action
            elif isinstance(action, MoveUpAction):
                self.move_up_action = action
            elif isinstance(action, PointerAction):
                self.pointer_action = action
            elif isinstance(action, ShowComponentPathAction):
                self.show_component_path_action = action
            elif isinstance(action, HexNumbersAction):
                self.hex_numbers_action = action

    def run_swing(self, func):
        # implement this method to run the given function in a Swing thread
        pass

    def end_transaction(self, commit):
        # implement this method to end the transaction with the given status
        pass

    def install_provider(self, provider):
        # implement this method to install the given provider
        pass

    def waitForSwing(self):
        # implement this method to wait for Swing operations to complete
        pass
