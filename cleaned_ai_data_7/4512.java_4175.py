import re
from typing import Pattern

class JavaScriptProvider:
    BLOCK_COMMENT_START = re.compile(r'\/\*')
    BLOCK_COMMENT_END = re.compile(r'\*\//')

    def __init__(self):
        self.bundle_host = GhidraScriptUtil.get_bundle_host()

    def get_bundle_for_source(self, source_file: ResourceFile) -> 'GhidraSourceBundle':
        if not isinstance(source_file, ResourceFile):
            raise TypeError('source_file must be a ResourceFile')

        source_dir = GhidraScriptUtil.find_source_directory_containing(source_file)
        if source_dir is None:
            return None

        bundle = self.bundle_host.get_existing_ghidra_bundle(source_dir)

        return bundle

    def get_description(self) -> str:
        return 'Java'

    def get_extension(self) -> str:
        return '.java'

    def delete_script(self, source_file: ResourceFile) -> bool:
        try:
            osgi_bundle = self.get_bundle_for_source(source_file).get_osgi_bundle()
            if osgi_bundle is not None:
                self.bundle_host.deactivate_synchronously(osgi_bundle)
        except GhidraBundleException as e:
            Msg.error(self, 'Error while deactivating bundle for delete', e)

        return super().delete_script(source_file)

    def get_script_instance(self, source_file: ResourceFile, writer) -> 'GhidraScript':
        try:
            clazz = self.load_class(source_file, writer)
            object_ = clazz.get_declared_constructor().new_instance()

            if isinstance(object_, GhidraScript):
                script = object_
                script.set_source_file(source_file)

                return script

            message = f'Not a valid Ghidra script: {source_file.name}'
            writer.write(message + '\n')
            Msg.error(self, message)
        except (ClassNotFoundException, InstantiationException, IllegalAccessException) as e:
            raise e
        except Exception as e:
            raise ClassNotFoundException('', e)

    def load_class(self, source_file: ResourceFile, writer):
        bundle = self.get_bundle_for_source(source_file)
        if bundle is None:
            raise ClassNotFoundException(f'Failed to find source bundle containing script: {source_file}')

        self.bundle_host.activate_all([bundle], TaskMonitor.DUMMY, writer)

        classname = bundle.class_name_for_script(source_file)
        clazz = bundle.get_osgi_bundle().load_class(classname)  # throws ClassNotFoundException

        return clazz

    def create_new_script(self, new_script: ResourceFile, category):
        script_name = new_script.name
        className = script_name
        dotpos = script_name.rfind('.')
        if dotpos >= 0:
            className = script_name[:dotpos]

        writer = PrintWriter(new FileWriter(new_script.file(False)))

        self.write_header(writer, category)

        writer.write('import ghidra.app.script.GhidraScript;\n')

        for pkg in Package.get_packages():
            if pkg.name.startswith('ghidra.program.model.'):
                writer.write(f'import {pkg.name}.*;\n')

        writer.write('\n')
        writer.write(f'public class {className} extends GhidraScript {{\n')
        writer.write('\n')
        writer.write('    public void run() throws Exception {{\n')

        self.write_body(writer)

        writer.write('}}\n')
        writer.close()

    def get_block_comment_start(self) -> Pattern:
        return JavaScriptProvider.BLOCK_COMMENT_START

    def get_block_comment_end(self) -> Pattern:
        return JavaScriptProvider.BLOCK_COMMENT_END

    def get_comment_character(self):
        return '//'

    @staticmethod
    def certify_header_start():
        return '/*  ###'

    @staticmethod
    def certify_header_end():
        return '*/'

    @staticmethod
    def certification_body_prefix():
        return '*'
