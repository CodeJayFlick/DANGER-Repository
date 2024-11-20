class VdexFactory:
    def get_vdex_header(self, reader):
        try:
            magic = reader.read_ascii_string(0, len(VdexConstants.MAGIC))
            version = reader.read_ascii_string(4, 4)
            if magic == Vdx_constants.MAGIC:
                if Vdx_constants.is_supported_version(version):
                    if version in [Vdx_constants.VERSION_OREO_RELEASE,
                                   Vdx_constants.VERSION_OREO_M2_RELEASE]:
                        return VdexHeaderOreo(reader)
                    elif version == Vdx_constants.VERSION_PIE_RELEASE:
                        return VdexHeaderPie(reader)
                    elif version == Vdx_constants.VERSION_10_RELEASE:
                        return VdexHeader10(reader)
                    elif version == Vdx_constants.VERSION_11_RELEASE:
                        return VdexHeader11(reader)
            raise UnsupportedVdexVersionException(magic, version)

    def load_vdex_header(self, program, monitor, log):
        if not program:
            return None

        vdex_program_name = os.path.splitext(program.name)[0]

        # First, look in current project for VDEX file.
        domain_file = program.domain_file
        parent_folder = domain_file.parent
        vdex_header = self.scan_project_folder(parent_folder, vdex_program_name,
                                               program, monitor, log)
        if not vdex_header:
            vdex_header = self.scan_project_folder(parent_folder.parent, vdex_program_name,
                                                  program, monitor, log)

        # Then, try to locate the VDEX on disk.
        oat_file_path = program.executable_path
        if oat_file_path.endswith('.odex') or oat_file_path.endswith('.oat'):
            vdex_file_path = os.path.splitext(oat_file_path)[0]
            file = File(vdex_file_path)
            with open(file, 'rb') as f:
                reader = BinaryReader(f, not program.language.is_big_endian())
                try:
                    return self.get_vdex_header(reader)
                except Exception as e:
                    log.append_msg("Unable to locate matching VDEX.")
        return None

    def scan_project_folder(self, parent_folder, vdex_program_name,
                            program, monitor, log):
        child = parent_folder.file(vdex_program_name)
        if child:
            try:
                consumer = object()
                vdex_program = (Program)(child.domain_object(consumer, True, True, monitor))
                with memoryfile() as f:
                    reader = BinaryReader(f, not program.language.is_big_endian())
                    return self.get_vdex_header(reader)
            finally:
                vdex_program.release(consumer)
        return None
