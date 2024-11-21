class TestKeyEventDispatcher:
    _focus_provider = None

    def dispatch_key_event(event):
        if not isinstance(event, KeyEvent):
            return False
        
        system_dispatcher = get_overridden_key_event_dispatcher()
        
        if system_dispatcher is None:
            # Not installed; nothing to do
            return False
        
        try:
            focus_provider._focus_owner = event.get_component()
            success = system_dispatcher.dispatch_key_event(event)
            return success
        finally:
            focus_provider._focus_owner = None

    def get_overridden_key_event_dispatcher():
        try:
            custom_dispatcher_class = globals()["docking.KeyBindingOverrideKeyEventDispatcher"]
            if not hasattr(custom_dispatcher_class, "instance"):
                return None  # Not installed
            
            custom_dispatcher = getattr(custom_dispatcher_class, "instance")
            
            focus_provider._focus_owner = event.get_component()
            TestUtils.invoke_instance_method("set_focus_owner_provider", custom_dispatcher, FocusOwnerProvider)
            
            return custom_dispatcher
        except KeyError:
            Msg.error(TestKeyEventDispatcher.__class__, "Unable to find the system KeyEventDispatcher")
            return None

    class TestFocusOwnerProvider(FocusOwnerProvider):
        _focus_owner = None
        
        def get_focus_owner(self):
            return self._focus_owner
        
        def get_active_window(self):
            if not self._focus_owner:
                return None
            
            if isinstance(self._focus_owner, Window):
                return self._focus_owner
            else:
                return SwingUtilities.window_for_component(self._focus_owner)
