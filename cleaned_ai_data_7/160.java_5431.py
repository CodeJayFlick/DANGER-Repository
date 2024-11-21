class ObjectPane:
    def get_container(self):
        pass  # To be implemented by subclass

    def get_target_object(self):
        pass  # To be implemented by subclass

    def get_selected_object(self):
        pass  # To be implemented by subclass

    def get_component(self):
        pass  # To be implemented by subclass

    def get_principal_component(self):
        pass  # To be implemented by subclass

    def update(self, container: 'ObjectContainer') -> List['object']:
        raise NotImplementedError("Method not implemented")

    def signal_data_changed(self, container: 'ObjectContainer'):
        raise NotImplementedError("Method not implemented")

    def signal_contents_changed(self, container: 'ObjectContainer'):
        raise NotImplementedError("Method not implemented")

    def signal_update(self, container: 'ObjectContainer'):
        raise NotImplementedError("Method not implemented")

    def get_name(self):
        pass  # To be implemented by subclass

    def set_focus(self, object1: 'TargetObject', focused: 'TargetObject'):
        pass  # To be implemented by subclass

    def set_root(self, root: 'ObjectContainer', target_object: 'TargetObject'):
        pass  # To be implemented by subclass
