class ProgramAnnotatedStringHandler:
    SUPPORTED_ANNOTATIONS = ["program"]

    def create_annotated_string(self, prototype_string: str, text: list[str], program: dict) -> tuple[AttributedString, int]:
        if len(text) <= 1:
            raise AnnotationException("Invalid symbol text")

        display_text = self.get_display_text(text)
        if display_text is None:
            raise AnnotationException("Invalid symbol text")

        return AttributedString(display_text), 0

    def get_display_text(self, text: list[str]) -> str | None:
        if len(text) > 2:
            buffer = StringBuffer()
            for i in range(2, len(text)):
                buffer.append(text[i]).append(" ")
            buffer.deleteCharAt(buffer.length - 1)
            return buffer.toString()

        symbol_text = self.get_unvalidated_display_text(text)
        if symbol_text is not None:
            program_name = text[1]
            return f"{program_name}@{symbol_text}"

        return text[1]

    def get_unvalidated_display_text(self, text: list[str]) -> str | None:
        symbol_path = self.get_symbol_path(text)
        return symbol_path.name if symbol_path is not None else None

    def get_symbol_path(self, text: list[str]) -> SymbolPath | None:
        raw_text = text[1]

        at_index = raw_text.find('@')
        if at_index < 0:
            return None

        raw_text = raw_text[at_index + 1:]
        return SymbolPath(raw_text)

    def get_program_text(self, text: list[str]) -> str | None:
        raw_text = text[1]

        at_index = raw_text.find('@')
        if at_index < 0:
            return raw_text

        return raw_text[:at_index]

    def handle_mouse_click(self, annotation_parts: list[str], navigatable: dict, service_provider: dict) -> bool:
        project_data_service = service_provider.get("ProjectDataService")
        project_data = project_data_service.get_project_data()

        folder = project_data.root_folder

        program_name = self.get_program_text(annotation_parts)
        path = FilenameUtils.name(program_name)

        if len(path) > 0:
            path = f"{FilenameUtils.separators_to_unix(path)}{"/"}"
            folder = project_data.get_folder(path)

        if folder is None:
            Msg.show_info(self, "No Folder", f"Unable to locate folder by the name {path}")
            return True

        program_file = self.find_program_by_name(program_name, folder)
        if program_file is None:
            Msg.show_info(self, "No Program", f"Unable to locate a program by the name {program_name}.")
            return True

        symbol_path = self.get_symbol_path(annotation_parts)

        navigate(program_file, symbol_path, navigatable, service_provider)

        return True

    def navigate(self, program_file: dict, symbol_path: SymbolPath | None, navigatable: dict, service_provider: dict):
        go_to_service = service_provider.get("GoToService")
        if go_to_service is None:
            Msg.show_warn(self, "Service Missing", f"This annotation requires the GoToService to be enabled.")
            return

        program_manager = service_provider.get("ProgramManager")

        program = program_manager.open_program(program_file, DomainFile.DEFAULT_VERSION, ProgramManager.OPEN_HIDDEN)
        if program is None:
            return  # cancelled

        if symbol_path is not None:  # no symbol; just open and go to the program
            start_address = program.memory.min_address
            go_to_service.go_to(navigatable, ProgramLocation(program, start_address), program)

    def find_program_by_name(self, program_text: str, folder: dict) -> DomainFile | None:
        files = folder.get_files()
        for file in files:
            if file.name == program_text:
                return file

        folders = folder.get_folders()
        for sub_folder in folders:
            domain_file = self.find_program_by_name(program_text, sub_folder)
            if domain_file is not None:
                return domain_file

        return None


class AnnotationException(Exception):
    pass
