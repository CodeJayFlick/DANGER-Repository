class BinaryColumnAdapter:
    def get_value_class(self):
        return str

    def get_key_value(self, rec):
        bytes = (rec.key_field.get_binary_data()).tobytes()
        if len(bytes) > 0:
            buf = f"byte[{len(bytes)}] = "
            for i in range(min(len(bytes), 20)):
                buf += f"{bytes[i]},"
            if len(bytes) > 20:
                buf += "...'"
        else:
            buf = "null"
        return buf

    def get_value(self, rec, col):
        bytes = rec.get_binary_data(col)
        if bytes is None:
            return "null"
        buf = f"byte[{len(bytes)}] = "
        for i in range(min(len(bytes), 20)):
            buf += f"{bytes[i]},"
        if len(bytes) > 20:
            buf += "...'"
        return buf
