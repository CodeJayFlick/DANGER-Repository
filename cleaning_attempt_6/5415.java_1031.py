class MSCoffLoader:
    MS_COFF_NAME = "MS Common Object File Format (COFF)"

    def is_microsoft_format(self):
        return True

    def get_name(self):
        return self.MS_COFF_NAME

    def is_case_insensitive_library_filenames(self):
        return True


# Example usage
loader = MSCoffLoader()
print(loader.get_name())  # prints: MS Common Object File Format (COFF)
print(loader.is_microsoft_format())  # returns: True
print(loader.is_case_insensitive_library_filenames())  # returns: True
