class ParameterStore:
    def __init__(self):
        self.manager = None
        self.parameter_map = {}
        self.device_map = {}
        self.copy = False
        self.parameter_server = None

    def set_parameter_server(self, parameter_server, devices):
        if not isinstance(devices, list) or len(devices) == 0:
            raise ValueError("Devices must be a non-empty list")
        for device in devices:
            if device_map.get(device) is not None:
                raise ValueError("Duplicated devices are not allowed.")
        self.parameter_server = parameter_server
        self.device_map.clear()
        for i, device in enumerate(devices):
            self.device_map[device] = i

    def update_all_parameters(self):
        for entry in self.parameter_map.items():
            param_id, data = entry
            if data.requires_gradient:
                params = [array.copy() for array in data]
                self.parameter_server.update(param_id, params)

    def get_value(self, parameter, device, training=False):
        if not isinstance(parameter, dict) or 'id' not in parameter:
            return None
        param_id = parameter['id']
        index = self.device_map.get(device)
        data = self.parameter_map.get(param_id, new ParameterData(parameter))
        if data.is_empty():
            array = parameter['array']
            if self.parameter_server is not None:
                # initialize on parameter store for first time
                self.parameter_server.init(param_id, [array])
                arrays = []
                for entry in self.device_map.items():
                    dev, i = entry
                    if i == index and array.get_device() == dev:
                        arrays.append(array)
                    else:
                        arrays.append(array.to(device))
            else:
                if not (self.copy or array.get_device() == device):
                    array = array.to(device)
                data.add(array)
        return data[index]

    def get_manager(self):
        return self.manager

    def sync(self):
        for entry in self.parameter_map.items():
            param_id, data = entry
            data.sync()

class ParameterData:
    def __init__(self, parameter):
        self.parameter = parameter
        self.list = []

    @property
    def is_empty(self):
        return len(self.list) == 0

    def add(self, array):
        self.list.append(array)

    def get(self, index):
        return self.list[index]

    def to_array(self):
        return [array.copy() for array in self.list]

    @property
    def requires_gradient(self):
        return self.parameter['requires_gradient']

    def sync(self):
        if not self.is_empty:
            array = self.parameter['array']
            device = array.get_device()
            if index not in self.device_map or self.device_map[device] is None:
                # model's parameters maybe loaded on different device than any of training devices.
                self.list[0].copy_to(array)
