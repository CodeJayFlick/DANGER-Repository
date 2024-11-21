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
