import io

class Pdb400:
    def __init__(self, msf: 'AbstractMsf', pdb_options):
        super().__init__(msf, pdb_options)

    def deserialize_identifiers_only(self, monitor) -> None:
        reader = self.get_directory_reader(monitor)
        self.deserialize_version_signature_age(reader)

    @property
    def directory_reader(self) -> callable:
        pass

    def deserialize_directory(self, monitor) -> None:
        reader = self.directory_reader(monitor)
        self.deserialize_version_signature_age(reader)
        self.deserialize_parameters(reader, monitor)

    def dump_directory(self, writer: io.TextIOBase) -> None:
        builder = StringBuilder()
        builder.append(str(self.dump_version_signature_age()))
        builder.append("\n")
        builder.append(str(self.dump_parameters()))
        writer.write(builder.toString())

class AbstractMsf:
    pass

class PdbReaderOptions:
    pass
