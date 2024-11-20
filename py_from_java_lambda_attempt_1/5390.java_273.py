Here's your Java code translated into Python:

```Python
class GzfLoader:
    GZF_NAME = "GZF Input Format"

    def get_tier(self):
        return "SPECIALIZED_TARGET_LOADER"

    def get_tier_priority(self):
        return 0

    def validate_options(self, provider, load_spec, options, program):
        if options and len(options) > 0:
            return "GzfLoader takes no options"
        else:
            return None

    def get_default_options(self, provider, load_spec, domain_object, load_into_program):
        return []

    def load(self, provider, program_name, program_folder, load_spec, options, message_log, consumer, monitor):
        if not program_folder:
            dobj = self.load_packed_program_database(provider, program_name, consumer, monitor)
        else:
            df = self.do_load(provider, program_name, program_folder, monitor)
            success = False
            try:
                if df.get_content_type() != "PROGRAM_CONTENT_TYPE":
                    raise IOException("File imported is not a Program: " + program_name)
                monitor.set_message("Opening " + program_name)
                dobj = df.get_domain_object(consumer, True, False, monitor)
                success = True
            finally:
                if not success:
                    df.delete()
        return [dobj]

    def load_packed_program_database(self, provider, program_name, consumer, monitor):
        file = provider.file
        packed_database = PackedDatabase.get_packed_database(file, True, monitor)
        success = False
        dbh = None
        try:
            if packed_database.get_content_type() != "PROGRAM_CONTENT_TYPE":
                raise IOException("File imported is not a Program: " + program_name)

            monitor.set_message("Restoring " + file.name)

            dbh = packed_database.open(monitor)
            dobj = ProgramDB(dbh, DBConstants.UPGRADE, monitor, consumer)
            success = True
        finally:
            if not success:
                if dbh:
                    dbh.close()  # also disposes packed database object
                else:
                    packed_database.dispose()
        return dobj

    def load_into(self, provider, load_spec, options, message_log, program, monitor):
        raise UnsupportedOperationException("cannot add GZF to program")

    def find_supported_load_specs(self, provider):
        try:
            if self.is_gzf_file(provider):
                return [LoadSpec(self, 0, False)]
        except IOException as e:
            print(f"Error: {e}")
        return []

    def get_preferred_filename(self, provider):
        return os.path.splitext(provider.name)[0]

    def do_load(self, provider, program_name, program_folder, monitor):
        file = provider.file
        folder = program_folder

        monitor.set_message("Restoring " + file.name)

        df = folder.create_file(program_name, file, monitor)
        return df

    @staticmethod
    def is_gzf_file(provider):
        if not provider.name.lower().endswith(".gzf"):
            return False
        try:
            with provider.open('rb') as f:
                return ItemSerializer.is_packed_file(f)
        except Exception as e:
            print(f"Error: {e}")
        return False

    def get_name(self):
        return self.GZF_NAME


class LoadSpec:
    pass


from io import IOException
import os
```

Please note that this is a direct translation from Java to Python and might not be the most idiomatic or efficient way of writing Python code.