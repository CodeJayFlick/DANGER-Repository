Here is the translation of the Java code into Python:

```Python
class NewGuid:
    def __init__(self, conv, guid_str, delim, guid_type, has_version):
        self.type = guid_type
        
        stripped_guid = guid_str.replace(delim, "").strip()
        if len(stripped_guid) != 32: 
            print("ERROR PARSING GUID:", guid_str)
        
        data = [0xFFFFFFFFL & int(striped_guid[:8], 16),
                (0xFFFFFFFFL & int((striped_guid[8:16]).ljust(8, "0"), 16)),
                (0xFFFFFFFFL & int((stripped_guid[16:24]).ljust(8, "0"), 16)),
                (0xFFFFFFFFL & int((stripped_guid[24:32]).ljust(8, "0"), 16))]
        
        for i in range(len(data)):
            conv.getBytes(int(data[i]), bytes(allBytes), i*4)
            
        left = guid_str.strip().split(" ")[36]
        if has_version:
            vpos = left.find("v")
            if vpos > -1: 
                version = left[:vpos].strip()
                sppos = left[vpos:].find(" ")
                name = left[sppos+1:]
        
    def __init__(self, conv, bytes, offset):
        for i in range(len(data)):
            data[i] = 0xFFFFFFFFL & int.from_bytes(bytes[offset+i*4:offset+(i+1)*4], 'little')
            
    def to_string(self, delim, use_name=False):
        if name and use_name:
            return name
        else:
            retVal = str(type) + delim
            for i in range(len(data)):
                retVal += hex(int.from_bytes(bytes(allBytes)[i*4:(i+1)*4], 'little'))[2:] + delim
            
    def is_ok(self):
        for d in data:
            if int(d) != 0xFFFFFFFFL or int(d) == 0:
                return True
        return False
    
    @staticmethod
    def is_ok_for_guid(bytes, offset):
        if len(bytes) < offset+16: 
            return False
        
        if bytes[offset+7] == 0x00 and bytes[offset+8] == 0xC0 and bytes[offset+15] == 0x46:
            return True
        
        if (bytes[offset+7] >= 0x10 and bytes[offset+7] <= 0x12) and (bytes[offset+8]&0xC0) == 0x80:
            return True
        
        if ((bytes[offset+7]&0xF0) == 0x40) and ((bytes[offset+8]&0xC0) == 0x80):
            return True
        else: 
            return False
    
    @staticmethod
    def is_zero_guid(bytes, offset):
        if len(bytes) < offset+16:
            return False
        
        for i in range(16): 
            if bytes[offset+i] != 0:
                return False
        return True
    
    def __eq__(self, test):
        if not isinstance(test, NewGuid):
            return False
        
        test_bytes = bytearray(test.get_bytes())
        
        for i in range(len(allBytes)):
            if allBytes[i] != test_bytes[i]:
                return False
        
        return True
    
    def __hash__(self):
        return int(data[0]) ^ int(data[1]) ^ int(data[2]) ^ int(data[3])
    
    def get_bytes(self): 
        return bytes(allBytes)
    
    def get_name(self): 
        return self.to_string("-", True)
    
    def get_version(self): 
        return version
    
    def get_type(self):
        return type
```

Please note that the conversion is not a direct translation. Python does not support Java's syntax and data types directly, so some changes were made to adapt it to Python.