import os
from utilities.util import ArrayUtilities

class JavaClassDecompilerFileSystemFactory:
    def get_bytes_required(self):
        return len(JavaClassConstants.MAGIC_BYTES)

    def probe_start_bytes(self, container_fsrl, start_bytes):
        if JadProcessWrapper.is_jad_present() and \
           ArrayUtilities.array_ranges_equals(start_bytes, 0, 
                                             JavaClassConstants.MAGIC_BYTES, 0,
                                             len(JavaClassConstants.MAGIC_BYTES)) and \
           "class".casefold() == os.path.splitext(container_fsrl.name)[1].casefold():
            return True
        else:
            return False

    def create(self, target_fsrl, provider, fs_service, monitor):
        try:
            fs = JavaClassDecompilerFileSystem(target_fsrl, provider, fs_service, monitor)
            return fs
        except (IOException, CancelledException) as e:
            raise Exception("Error creating file system: " + str(e))
