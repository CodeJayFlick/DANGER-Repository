import io
from zipfile import ZipFile, ZIP_DEFLATED
import os
import hashlib


class DexToJarFileSystem:
    def __init__(self):
        self.jar_file = None

    def get_jar_file(self):
        return self.jar_file

    def get_byte_provider(self, file_path, monitor=None):
        if file_path == self.get_jar_file().get_fsrl():
            return self._convert_dex_to_jar(monitor)
        else:
            return None

    def _convert_dex_to_jar(self, monitor):
        with ZipFile('output.jar', 'w', ZIP_DEFLATED) as zip_file:
            try:
                dex_file = DexFileReader().read_bytes()
                file_node = DexFileNode(dex_file)
                reader = DexFileReader()
                reader.accept(file_node)

                class_visitor_factory = ClassVisitorFactory()

                for name in [file_node.get_class_name()]:
                    visitor = new ClassVisitor(Opcodes.ASM4, ClassWriter(COMPUTE_MAXS))
                    writer = ClassWriter(visit_end=visitor.visit_end)
                    data = writer.to_bytes()
                    zip_file.write(data)

            except Exception as e:
                print(f"ASM fail to generate .class file: {name}")
        return

    def get_listing(self):
        if self.jar_file is None or self.jar_file.get_fsrl() == root:
            return [self.jar_file]
        else:
            return []

    def is_valid(self, monitor=None):
        return DexConstants.is_dex_file()

    def open(self, monitor=None):
        jar_bp = self._convert_dex_to_jar(monitor)
        if jar_bp.get_fsrl() == root:
            base_name = os.path.splitext(root)[0]
            jar_name = f"{base_name}.jar"
            fsrl = root.with_path_md5(jar_name, jar_bp.get_fsrl().get_md5())
            self.jar_file = GFileImpl.from_filename(self, root, base_name + ".jar", False,
                                                      jar_bp.length(), fsrl)
        return

    def close(self):
        super.close()
