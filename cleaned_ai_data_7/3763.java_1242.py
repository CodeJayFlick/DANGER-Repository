class DataTypePreview:
    MAX_PREVIEW_LENGTH = 150

    def __init__(self, dt):
        self.dt = dt

    def get_name(self):
        return self.dt.name

    def get_preview(self, memory, addr):
        try:
            mb = DumbMemBufferImpl(memory, addr)
            dti = self.dt.get_data_type_instance(mb, self.MAX_PREVIEW_LENGTH)
            if dti is None:
                return ""

            length = min(dti.length, self.MAX_PREVIEW_LENGTH)
            return self.dt.representation(mb, SettingsImpl(), length)

        except Exception as e:
            return "ERROR: unable to create preview"

    def get_data_type(self):
        return self.dt

    def __str__(self):
        return self.get_name()

    def compare_to(self, p):
        if isinstance(p, DataTypePreview):
            dtp = p
            return self.get_name().casefold() == dtp.get_name().casefold()
        else:
            return str(self).casefold() == str(p)
