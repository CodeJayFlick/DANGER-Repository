class DynamicDataType:
    def __init__(self, name):
        self.map = {}
        self.default_settings = {}

    @property
    def default_settings(self):
        return self._default_settings

    @default_settings.setter
    def default_settings(self, value):
        self._default_settings = value

    def can_specify_length(self):
        return False

    def get_num_components(self, buf):
        comps = self.get_comps(buf)
        if comps is None or len(comps) == 0:
            return -1
        return len(comps)

    def get_comps(self, buf):
        addr = buf['address']
        comps = self.map.get(addr)
        if comps is None:
            comps = self.getAllComponents(buf)
            if comps is None:
                # data-type not valid at buf location
                return None
            self.map[addr] = comps
        return comps

    def get_component(self, ordinal, buf):
        comps = self.get_comps(buf)
        if comps is not None:
            try:
                return comps[ordinal]
            except IndexError:
                pass
        return None

    def get_components(self, buf):
        return self.get_comps(buf)

    def get_component_at(self, offset, buf):
        # TODO: This interface should be consistent with Structure
        comps = self.get_comps(buf)
        if comps is None:
            return None
        for comp in comps:
            if comp['offset'] <= offset < (comp['end_offset']):
                return comp

    def getAllComponents(self, buf):
        pass  # abstract method implementation


class DataTypeComponent:
    def __init__(self, name):
        self.offset = -1
        self.end_offset = -1
        self.length = -1

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, value):
        self._offset = value

    @property
    def end_offset(self):
        return self._end_offset

    @end_offset.setter
    def end_offset(self, value):
        self._end_offset = value

    @property
    def length(self):
        return self._length

    @length.setter
    def length(self, value):
        self._length = value


class MemBuffer:
    def __init__(self, address):
        self['address'] = address  # for compatibility with Java code
