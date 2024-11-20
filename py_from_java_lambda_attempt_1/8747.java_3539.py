Here is the translation of the Java code into Python:

```Python
class LinearFunctionAddressCorrelation:
    NAME = "LinearFunctionAddressCorrelation"

    def __init__(self, source_function, destination_function):
        self.source_function = source_function
        self.destination_function = destination_function
        self.cached_forward_address_map = {}

    def get_name(self):
        return self.NAME

    def get_correlated_destination_range(self, source_address, monitor=None):
        if not hasattr(self, 'cached_forward_address_map'):
            self.initialize(monitor)
        to_range = self.cached_forward_address_map.get(source_address)
        if to_range is None:
            percent_offset = self.find_percentage_from_function_start(source_address)
            destination_address = self.get_destination_address(percent_offset)
            to_range = (destination_address, destination_address)
        return to_range

    def initialize(self, monitor=None):
        if not hasattr(self, 'cached_forward_address_map'):
            self.cached_forward_address_map = {}
            self.compute_param_correlation()

    def find_percentage_from_function_start(self, address):
        src_body = self.source_function.body
        accumulated_length = 0
        for range_ in src_body:
            if range_.max_address < address:
                accumulated_length += range_.length
            else:
                if range_.contains(address):
                    accumulated_length += address - range_.min_address
                break
        percent_offset = (accumulated_length / len(src_body))
        return percent_offset

    def get_destination_address(self, percent_offset):
        src_body = self.destination_function.body
        offset = int(percent_offset * len(src_body) + 0.5)
        for address_range in src_body:
            if offset < address_range.length:
                return address_range.min_address + offset
            offset -= address_range.length
        return src_body.max_address

    def compute_param_correlation(self):
        source_count = self.source_function.parameter_count
        destination_count = self.destination_function.parameter_count
        source_parameters = [param for param in self.source_function.parameters]
        destination_parameters = [param for param in self.destination_function.parameters]
        all_match = False
        if source_count == destination_count:
            all_match = True
            map_ = {}
            for i, (source_param, dest_param) in enumerate(zip(source_parameters, destination_parameters)):
                source_data_type = source_param.data_type
                dest_data_type = dest_param.data_type
                source_length = source_data_type.length
                dest_length = dest_data_type.length
                min_address = source_param.min_address
                map_[min_address] = (dest_param.min_address, dest_param.min_address)
                if source_length != dest_length:
                    all_match = False
                    break
            if all_match:
                self.cached_forward_address_map.update(map_)
```

Note that Python does not have direct equivalents for Java's `Address`, `AddressRange`, and other classes. The code has been adapted to use built-in Python data types such as tuples, lists, dictionaries, etc., which are more suitable for the task at hand.