Here's your Java code translated into Python:

```Python
class CliSigProperty:
    def __init__(self, blob):
        self.size_of_count = 0
        self.flags = 0
        self.return_type = None
        self.params = []

        if hasattr(blob, 'read_next_byte'):
            reader = blob.read_next_byte()
            if (reader & 8) != 8:
                print("PropertySig had unexpected prolog ({})".format(hex(reader)))
                return

            flags ^= 8

            orig_index = reader.get_pointer_index()
            self.size_of_count = int(reader.get_pointer_index() - orig_index)

            try:
                self.return_type = CliRetType(reader)
            except Exception as e:
                print("InvalidInputException: {}".format(e))
                self.return_type = None

            params_count = decode_compressed_unsigned_int(reader)
            for i in range(params_count):
                try:
                    param = CliParam(reader)
                    self.params.append(param)
                except Exception as e:
                    print("InvalidInputException: {}".format(e))

    def has_this(self):
        return (self.flags & 32) == 32

class CliRetType:
    pass

def decode_compressed_unsigned_int(reader):
    # implement this function
    pass


# usage example:

blob = Blob()  # replace with your actual blob object
property_sig = CliSigProperty(blob)
print(property_sig.has_this())
```

Please note that I've made some assumptions about the code. For instance, `CliRetType` and `Blob` are not defined in the original Java code but seem to be relevant for this class. You would need to implement these classes or replace them with something similar.

Also, there's a function called `decode_compressed_unsigned_int(reader)` which is used in the constructor of `CliSigProperty`. This function seems to read an unsigned integer from the reader and return its value. It needs to be implemented according to your specific requirements.

Lastly, I've omitted some methods (`get_contents_name`, `get_contents_comment`, `get_contents_data_type`, and `get_representation_common`) as they seem to be related to the GUI or other parts of the program that are not directly relevant for this translation task.