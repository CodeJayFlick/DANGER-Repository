class MonitorTest:
    def get_hash_code(self, o):
        if isinstance(o, object):
            return hash(o)
        else:
            raise TypeError("Input must be an instance of 'object'")

    def get_hash_code2(self, o):
        x = 0
        try:
            with lock():
                x = hash(o)
        except Exception as e:
            print(f"An error occurred: {e}")
        return x

lock = threading.Lock()
