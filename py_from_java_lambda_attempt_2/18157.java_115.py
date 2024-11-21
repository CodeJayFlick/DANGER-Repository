Here is the translation of the Java code into Python:

```Python
class SDTEncoder:
    def __init__(self):
        self.upper_door = float('-inf')
        self.lower_door = float('inf')
        self.comp_deviation = -1
        self.comp_min_time = 0
        self.comp_max_time = float('inf')
        self.is_first_value = True

    def encode_float(self, time: int, value: float) -> bool:
        if self.is_first_value(time, value):
            return True
        
        if time - self.last_stored_timestamp <= self.comp_min_time:
            return False
        
        if time - self.last_stored_timestamp >= self.comp_max_time:
            self.reset(time, value)
            return True

        cur_upper_slope = (value - self.last_stored_float - self.comp_deviation) / (time - self.last_stored_timestamp)
        if cur_upper_slope > self.upper_door:
            self.upper_door = cur_upper_slope
        
        cur_lower_slope = (value - self.last_stored_float + self.comp_deviation) / (time - self.last_stored_timestamp)
        if cur_lower_slope < self.lower_door:
            self.lower_door = cur_lower_slope

        if self.upper_door >= self.lower_door:
            self.store_last_read_pair(time, value)
            return True
        
        self.last_stored_float = value
        self.last_stored_timestamp = time
        return False
    
    def encode_long(self, time: int, value: int) -> bool:
        if self.is_first_value(time, value):
            return True
        
        if time - self.last_stored_timestamp <= self.comp_min_time:
            return False
        
        if time - self.last_stored_timestamp >= self.comp_max_time:
            self.reset(time, value)
            return True

        cur_upper_slope = (value - self.last_stored_long - self.comp_deviation) / (time - self.last_stored_timestamp)
        if cur_upper_slope > self.upper_door:
            self.upper_door = cur_upper_slope
        
        cur_lower_slope = (value - self.last_stored_long + self.comp_deviation) / (time - self.last_stored_timestamp)
        if cur_lower_slope < self.lower_door:
            self.lower_door = cur_lower_slope

        if self.upper_door >= self.lower_door:
            self.store_last_read_pair(time, value)
            return True
        
        self.last_stored_long = value
        self.last_stored_timestamp = time
        return False
    
    def encode_int(self, time: int, value: int) -> bool:
        if self.is_first_value(time, value):
            return True
        
        if time - self.last_stored_timestamp <= self.comp_min_time:
            return False
        
        if time - self.last_stored_timestamp >= self.comp_max_time:
            self.reset(time, value)
            return True

        cur_upper_slope = (value - self.last_stored_int - self.comp_deviation) / (time - self.last_stored_timestamp)
        if cur_upper_slope > self.upper_door:
            self.upper_door = cur_upper_slope
        
        cur_lower_slope = (value - self.last_stored_int + self.comp_deviation) / (time - self.last_stored_timestamp)
        if cur_lower_slope < self.lower_door:
            self.lower_door = cur_lower_slope

        if self.upper_door >= self.lower_door:
            self.store_last_read_pair(time, value)
            return True
        
        self.last_stored_int = value
        self.last_stored_timestamp = time
        return False
    
    def encode_double(self, time: int, value: float) -> bool:
        if self.is_first_value(time, value):
            return True
        
        if time - self.last_stored_timestamp <= self.comp_min_time:
            return False
        
        if time - self.last_stored_timestamp >= self.comp_max_time:
            self.reset(time, value)
            return True

        cur_upper_slope = (value - self.last_stored_double - self.comp_deviation) / (time - self.last_stored_timestamp)
        if cur_upper_slope > self.upper_door:
            self.upper_door = cur_upper_slope
        
        cur_lower_slope = (value - self.last_stored_double + self.comp_deviation) / (time - self.last_stored_timestamp)
        if cur_lower_slope < self.lower_door:
            self.lower_door = cur_lower_slope

        if self.upper_door >= self.lower_door:
            self.store_last_read_pair(time, value)
            return True
        
        self.last_stored_double = value
        self.last_stored_timestamp = time
        return False
    
    def encode(self, timestamps: list[int], values: list[Union[float, int]], batch_size: int) -> int:
        index = 0
        for i in range(batch_size):
            if getattr(self, f'encode_{values[i].__class__.__name__.lower()}')(timestamps[i], values[i]):
                timestamps[index] = self.last_stored_timestamp
                values[index] = getattr(self, f'get{values[i].__class__.__name__[0].upper() + "Value"}')()
                index += 1
        
        return index
    
    def is_first_value(self, time: int, value) -> bool:
        if self.is_first_value:
            self.is_first_value = False
            self.last_read_timestamp = time
            self.last_read_float = value
            self.last_stored_timestamp = time
            self.last_stored_float = value
            return True
        
        return False
    
    def reset(self) -> None:
        self.upper_door = float('-inf')
        self.lower_door = float('inf')

    def store_last_read_pair(self, time: int, value) -> None:
        self.last_stored_timestamp = time
        if isinstance(value, (int, float)):
            setattr(self, f'last_stored_{value.__class__.__name__.lower()}', value)
        else:
            raise ValueError("Invalid type for value")

    def set_comp_deviation(self, comp_deviation: float) -> None:
        self.comp_deviation = comp_deviation

    def get_comp_deviation(self) -> float:
        return self.comp_deviation
    
    def set_comp_min_time(self, comp_min_time: int) -> None:
        self.comp_min_time = comp_min_time

    def get_comp_min_time(self) -> int:
        return self.comp_min_time
    
    def set_comp_max_time(self, comp_max_time: int) -> None:
        self.comp_max_time = comp_max_time

    def get_comp_max_time(self) -> int:
        return self.comp_max_time
    
    def get_last_stored_timestamp(self) -> int:
        return self.last_stored_timestamp
    
    def get_int_value(self) -> int:
        return self.last_stored_int
    
    def get_double_value(self) -> float:
        return self.last_stored_double
    
    def get_long_value(self) -> int:
        return self.last_stored_long
    
    def get_float_value(self) -> float:
        return self.last_stored_float
```

Please note that Python does not have a direct equivalent to Java's `long` type. In this translation, I used the built-in integer type (`int`) for timestamps and values of types `int`, `float`. For timestamps and values of type `double`, I used the built-in floating-point number type (`float`).