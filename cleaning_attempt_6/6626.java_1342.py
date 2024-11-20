class FuncDBsmall:
    def __init__(self):
        self.libraries = set()

    # Construct a DB from the current program, with a record for every function.
    def __init_from_program(self, prgm):
        self.libraries = set()
        self.libraries.add(LibraryRecord(prgm))

    # Merge another DB into this one.
    def merge_with(self, to_merge_in):
        self.libraries.update(to_merge_in.libraries)

    # Add a library to the database.
    def add_library(self, lib_rec):
        self.libraries.add(lib_rec)
        return

    def get_records(self):
        results = set()
        for lib in self.libraries:
            results.update(lib.get_records())
        return list(results)  # Convert back to list as Python doesn't have a direct equivalent of Java's TreeSet.

    # Find an entry of the database based on actual underlying function.
    def query_func(self, func):
        query_hash = FuncRecord(func)
        result = self.query(query_hash.hash_value)
        for entry in result:
            if entry.func == func:
                return [entry]
        return list(result)  # Return all matches.

    # Find an entry of the database based on hash. Returns all records with that hash.
    def query(self, hash):
        results = []
        temp = FuncRecord()
        temp.hash_value = hash
        for lib_rec in self.libraries:
            results.extend(lib_rec.query(hash))
        return results

    # DB is made up of libraries. To get a DB from a file/parser, look for the "funcDB" tag, and then pass the buck to the LibraryRecord class.
    def restore_xml(self, parser):
        parser.start("funcDB")
        while parser.peek().is_start():
            lib_rec = LibraryRecord()
            lib_rec.restore_xml(parser)
            self.add_library(lib_rec)
        parser.end()

    # Save DB to an XML file.
    def save_xml(self, fwrite):
        buf = StringBuffer()
        buf.append("<funcDB>\n")  # The XML tag for the entire DB.
        fwrite.write(buf.toString())
        for lib_rec in self.libraries:
            lib_rec.save_xml(fwrite)
        fwrite.write("</funcDB>\n")
