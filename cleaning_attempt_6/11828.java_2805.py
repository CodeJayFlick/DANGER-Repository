class CommentTypeFilterAddressIterator:
    def __init__(self, program, address_iterator, comment_type):
        self.listing = program.get_listing()
        self.address_iterator = address_iterator
        self.comment_type = comment_type
        self.next_address = None

    def remove(self):
        raise NotImplementedError("remove is not implemented")

    def has_next(self):
        if self.next_address is None:
            self.find_next()
        return self.next_address is not None

    def next(self):
        if self.has_next():
            address = self.next_address
            self.next_address = None
            return address
        return None

    def find_next(self):
        while True:
            try:
                address = next(self.address_iterator)
                comment = self.listing.get_comment(self.comment_type, address)
                if comment is not None:
                    self.next_address = address
                    break
            except StopIteration:
                pass

    def __iter__(self):
        return self


# Example usage:

class Program:
    def get_listing(self):
        # Your implementation here
        pass

def main():
    program = Program()
    iterator = CommentTypeFilterAddressIterator(program, iter(range(10)), 0)
    for address in iterator:
        print(address)

if __name__ == "__main__":
    main()

