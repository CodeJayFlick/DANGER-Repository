class CommentsDBAdapterV1:
    def __init__(self, handle, addr_map, create):
        self.addr_map = addr_map
        if create:
            comment_table = handle.create_table("Comments", "Address")
        else:
            try:
                comment_table = handle.get_table("Comments")
            except Exception as e:
                raise VersionException(f"Missing Table: {e}")
            if not isinstance(comment_table, dict):
                raise VersionException(VersionException.NEWER_VERSION)

    def get_record(self, addr):
        return comment_table[addr]

    def create_record(self, addr, comment_col, comment):
        record = {"Address": addr}
        for i in range(len(V1_NAMES)):
            if i == comment_col:
                record[V1_NAMES[i]] = comment
        try:
            comment_table.update(record)
        except Exception as e:
            raise IOException(f"Error creating record: {e}")
        return record

    def delete_record(self, addr):
        try:
            del comment_table[addr]
        except KeyError:
            pass  # Record not found or does not exist
        return True

    def delete_records(self, start_addr, end_addr):
        for i in range(int((end_addr - start_addr).to_bytes().hex(), 16), int(start_addr.to_bytes().hex(), 16) - 1, -1):
            try:
                del comment_table[i]
            except KeyError:
                pass  # Record not found or does not exist
        return True

    def update_record(self, record):
        try:
            comment_table.update(record)
        except Exception as e:
            raise IOException(f"Error updating record: {e}")

    def get_keys(self, start_addr, end_addr, at_start=False):
        if at_start:
            for i in range(int((end_addr - start_addr).to_bytes().hex(), 16), int(start_addr.to_bytes().hex(), 16) - 1, -1):
                yield (start_addr + i)
        else:
            for i in range(int(start_addr.to_bytes().hex(), 16), int(end_addr.to_bytes().hex(), 16)):
                yield start_addr + i

    def get_keys(self, set_view, forward=True):
        if forward:
            return self.get_keys(set_view.getMinAddress(), set_view.getMaxAddress())
        else:
            return self.get_records(set_view.getMaxAddress())

    def get_records(self, start_addr, end_addr, at_start=False):
        for addr in self.get_keys(start_addr, end_addr, at_start):
            yield comment_table[addr]

    def put_record(self, record):
        try:
            comment_table.update(record)
        except Exception as e:
            raise IOException(f"Error putting record: {e}")

    def get_record_count(self):
        return len(comment_table)

    def move_address_range(self, from_addr, to_addr, length, monitor=None):
        for i in range(int(length)):
            try:
                comment_table.update({str(from_addr + i): str(to_addr + i)})
            except Exception as e:
                raise CancelledException(f"Error moving address: {e}")
