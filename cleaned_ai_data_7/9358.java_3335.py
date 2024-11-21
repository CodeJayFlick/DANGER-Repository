class DockingKeyBindingAction:
    def __init__(self, tool: 'Tool', action_if: 'DockingActionIf', key_stroke):
        self.tool = tool
        self.docakble_action = action_if
        self.key_stroke = key_stroke

    @property
    def key_stroke(self) -> object:
        return self.key_stroke

    def is_enabled(self) -> bool:
        # always enable; this is a reserved binding and cannot be disabled
        return True

    def get_key_binding_precedence(self):
        raise NotImplementedError('Must implement abstract method')

    @property
    def key_binding_precedence(self) -> object:
        if not hasattr(self, '_key_binding_precedence'):
            self._key_binding_precedence = self.get_key_binding_precedence()
        return self._key_binding_precedence

    def is_reserved_keybinding_precedence(self) -> bool:
        return False

    def action_performed(self, e: 'ActionEvent') -> None:
        self.tool.set_status_info('')
        provider = self.tool.get_active_component_provider()
        context = self.get_local_context(provider)
        context.set_source_object(e.source)
        self.docakble_action.action_performed(context)

    @property
    def local_context(self) -> object:
        if not hasattr(self, '_local_context'):
            self._local_context = self.get_local_context(self.tool.get_active_component_provider())
        return self._local_context

    def get_local_context(self, provider: 'ComponentProvider') -> object:
        if provider is None:
            return ActionContext()
        
        action_context = provider.get_action_context(None)
        if action_context is not None:
            return action_context
        
        return ActionContext(provider, None)

class Tool:
    pass

class DockingActionIf:
    def action_performed(self):
        raise NotImplementedError('Must implement abstract method')

class ComponentProvider:
    @property
    def active_component_provider(self) -> object:
        raise NotImplementedError('Must implement property')
    
    def get_action_context(self, source: 'object') -> object:
        raise NotImplementedError('Must implement method')

class ActionContext:
    pass

# Usage example:

tool = Tool()
action_if = DockingActionIf()

docking_key_binding_action = DockingKeyBindingAction(tool, action_if, KeyStroke())
