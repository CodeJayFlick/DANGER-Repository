class SettingsImpl:
    def __init__(self):
        self.map = {}
    
    @staticmethod
    def NO_SETTINGS():
        return SettingsImpl()

    def changed(self):
        if hasattr(self, 'listener') and self.listener:
            event = None
            if hasattr(self, 'changeSourceObj'):
                event = ChangeEvent(self.changeSourceObj)
            self.listener.state_changed(event)

class ChangeEvent:
    def __init__(self, source_obj):
        self.source_obj = source_obj

class SettingsImpl(ChangeEventListener):
    def __init__(self, listener=None, change_source_obj=None):
        super().__init__()
        if hasattr(listener, 'state_changed'):
            self.listener = listener
        else:
            self.listener = None
        
        if change_source_obj is not None and isinstance(change_source_obj, object):
            self.changeSourceObj = change_source_obj
        else:
            self.changeSourceObj = None

    def __str__(self):
        return str(self.map)

    @property
    def isEmpty(self):
        return len(self.map) == 0
    
    def get_long(self, name):
        value = self.map.get(name)
        if value is None and hasattr(self, 'defaultSettings'):
            value = self.defaultSettings.get_long(name)
        return value

    def get_string(self, name):
        value = self.map.get(name)
        if value is None and hasattr(self, 'defaultSettings'):
            value = self.defaultSettings.get_string(name)
        return value

    def get_byte_array(self, name):
        bytes_ = self.map.get(name)
        if bytes_ is None and hasattr(self, 'defaultSettings'):
            bytes_ = self.defaultSettings.get_byte_array(name)
        return bytes_

    def set_long(self, name, value):
        self.map[name] = value
        self.changed()

    def set_string(self, name, value):
        self.map[name] = value
        self.changed()

    def set_byte_array(self, name, value):
        self.map[name] = value
        self.changed()

    def clear_setting(self, name):
        if name in self.map:
            del self.map[name]
            self.changed()
    
    @property
    def names(self):
        return list(self.map.keys())

    def get_value(self, name):
        value = self.map.get(name)
        if value is None and hasattr(self, 'defaultSettings'):
            value = self.defaultSettings.get_value(name)
        return value

    def set_value(self, name, value):
        if isinstance(value, (int, str)):
            self.map[name] = value
            self.changed()
        else:
            raise ValueError("Value is not a known settings type")

    @property
    def default_settings(self):
        return getattr(self, 'defaultSettings', None)

    def set_default_settings(self, settings):
        if isinstance(settings, SettingsImpl):
            setattr(self, 'defaultSettings', settings)
    
    def clear_all_settings(self):
        self.map.clear()
        self.changed()

class ChangeEventListener:
    def state_changed(self, event=None):
        pass
