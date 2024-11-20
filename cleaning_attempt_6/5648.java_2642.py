class ProgramLocationColumnTypeMapper:
    def convert(self, program_location: 'ProgramLocation') -> 'Address':
        return program_location.get_address()

# Note that in Python, we don't need to define a class for every type like in Java.
