class MarkerLocation:
    def __init__(self, markers, program, addr, x, y):
        self.markers = markers
        self.program = program
        self.addr = addr
        self.x = x
        self.y = y

    @property
    def program(self):
        return self._program

    @program.setter
    def program(self, value):
        self._program = value

    @property
    def addr(self):
        return self._addr

    @addr.setter
    def addr(self, value):
        self._addr = value

    @property
    def markers(self):
        return self._markers

    @markers.setter
    def markers(self, value):
        self._markers = value

    def get_program(self):
        return self.program

    def get_addr(self):
        return self.addr

    def get_marker_manager(self):
        return self.markers

    def get_x(self):
        return self.x

    def get_y(self):
        return self.y


class Program:
    pass


class Address:
    pass


class MarkerSet:
    pass
