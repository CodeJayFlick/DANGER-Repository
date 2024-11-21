import os
from ghidra_script import GhidraScript
from fid_db import FidDB
from file_manager import FidFileManager


class ListFunctions(GhidraScript):
    def write_functions(self, fid_db: FidDB, out_file: str) -> None:
        hash = 0x80000000L
        while True:
            long_obj = fid_db.find_full_hash_value_at_or_after(hash)
            if long_obj is None:
                break
            hash += 1
            func_list = fid_db.find_functions_by_full_hash(long_obj.long_value())
            for rec in func_list:
                with open(out_file, 'a') as out_writer:
                    out_writer.write(rec.get_domain_path() + '\n')
                    out_writer.write('  ')
                    out_writer.write(rec.get_name() + '\n')

    def run(self) -> None:
        fid_file_manager = FidFileManager()
        user_fid_files = fid_file_manager.get_fid_files()
        if not user_fid_files:
            return
        chosen_fid_file = ask_choice("List Functions", "Choose FID database", user_fid_files, user_fid_files[0])

        try:
            with FidDB(chosen_fid_file) as fid_db:
                out_file_path = ask_file("Output file", "Choose output file: ")
                if not out_file_path:
                    return
                self.write_functions(fid_db, out_file_path)
        except VersionException as e:
            print(f"Failed to open FID database. May need to regenerate with this version of Ghidra.")
