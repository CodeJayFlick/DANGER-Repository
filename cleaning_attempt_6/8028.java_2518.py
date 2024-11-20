class PdbParser:
    VC2_ID = 19941610  # 0x013048ea
    VC4_ID = 19950623  # 0x01306c1f
    VC41_ID = 19950814  # 0x01306cde
    VC50_ID = 19960307  # 0x013091f3
    VC98_ID = 19970604  # 0x0130ba2c
    VC70DEP_ID = 19990604  # 0x0131084c
    VC70_ID = 20000404  # 0x01312e94
    VC80_ID = 20030901  # 0x0131a5b5
    VC110_ID = 20091201  # 0x01329141
    VC140_ID = 20140508  # 0x013351dc

    def parse(filename, pdb_options, monitor):
        if not filename:
            raise ValueError("filename cannot be null")
        if not pdb_options:
            raise ValueError("pdbOptions cannot be null")
        if not monitor:
            raise ValueError("monitor cannot be null")

        msf = MsfParser.parse(filename, pdb_options, monitor)

        version_number = AbstractPdb.deserialize_version_number(msf, monitor)

        pdb = None
        match version_number:
            case VC2_ID | VC4_ID | VC41_ID | VC50_ID | VC98_ID | VC70DEP_ID:
                pdb = Pdb400(msf, pdb_options)
            case VC70_ID | VC80_ID | VC110_ID | VC140_ID:
                pdb = Pdb700(msf, pdb_options)
            case _:
                msf.close()
                raise PdbException(f"Unknown PDB Version: {version_number}")

        pdb.deserialize_identifiers_only(monitor)

        return pdb
