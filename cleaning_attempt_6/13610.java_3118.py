import os
from typing import List, Tuple

class OpenFileRunnable:
    def __init__(self, file_path: str):
        self.file_path = file_path

    def run(self) -> None:
        project_files = find_matching_files(self.file_path)
        user_file_choices = maybe_prompt_user_for_files_to_open(project_files)
        open_files(user_file_choices)

    def open_files(self, files_to_open: List[IFile]) -> None:
        if not files_to_open:
            return  # User cancelled
        for file in files_to_open:
            self.open_file(file)

    def open_file(self, file: IFile) -> None:
        try:
            IDE().open_editor(page=file)
        except PartInitException as e:
            EclipseMessageUtils.show_error_dialog("Unable to Open Script", "Couldn't open editor for {}".format(self.file_path))
        page.get_workbench_window().get_shell().force_active()

    def maybe_prompt_user_for_files_to_open(self, project_files: List[IFile]) -> Tuple[List[IFile], bool]:
        if not project_files:
            return [], False
        if len(project_files) == 1:
            return [project_files[0]], True

        # Look for any project ending in 'scripts' and assume that is the preferred project
        for i_file in project_files:
            project = i_file.get_project()
            name = project.name
            if name.lower().endswith("scripts"):
                return [project_files[0]], False

        page = EclipseMessageUtils.get_workbench_page()
        dialog = ElementListSelectionDialog(page.get_workbench_window().get_shell(), LabelProvider())
        dialog.set_title("Choose a File")
        displayable_files = format_strings(project_files)
        dialog.set_elements(displayable_files)
        dialog.set_message("Select a file to open")

        size = calculate_preferred_size_in_characters(displayable_files)
        dialog.set_size(size.width, size.height)

        results = dialog.open()
        result_files = [((DisplayableIFile(file)).get_file() for file in results)]
        return result_files[0], True

    def find_matching_files(self, path: str) -> List[IFile]:
        java_projects = GhidraProjectUtils.get_ghidra_projects()
        project_files = self.find_matching_files_in_projects(path, java_projects)
        if not project_files:
            try:
                for java_project in java_projects:
                    java_project.refresh_local(IResource.DEPTH_INFINITE, NullProgressMonitor())
            except CoreException as e1:
                EclipseMessageUtils.show_error_dialog("Unable to Open Script", "Unexpected Exception refreshing project")
                return []
        return self.find_matching_files_in_projects(path, java_projects)

    def find_matching_files_in_projects(self, path: str, projects: List[IJavaProject]) -> List[IFile]:
        files = []
        for project in projects:
            if not project.is_open():
                continue
            try:
                i_path = self.find_path_from_folder(path, project)
                if i_path is not None:
                    file = project.get_file(i_path)
                    files.append(file)
            except CoreException as e:
                EclipseMessageUtils.error("Unexpected exception accessing project members", e)
        return files

    def find_path_from_folder(self, path: str, resource: IResource) -> Tuple[str]:
        if not isinstance(resource, IContainer):
            return None
        container = resource
        members = container.members()
        for member in members:
            location = member.get_location()

            # Compare as files to bypass path separator issues
            file_for_path = os.path.normpath(path)
            file_for_location = os.path.normpath(str(location))
            if file_for_location == file_for_path:
                return str(member.get_project_relative_path())
            i_path = self.find_path_from_folder(path, member)
            if i_path is not None:
                return i_path
        return None

    def format_strings(self, project_files: List[IFile]) -> List[DisplayableIFile]:
        list_ = []
        for file in project_files:
            list_.append(DisplayableIFile(file))
        return list_

class DisplayableIFile:
    def __init__(self, i_file: IFile):
        self.file = i_file
        display_string = os.path.basename(i_file.get_location())
        self.display_string = display_string

    def get_file(self) -> IFile:
        return self.file

    def get_display_string(self) -> str:
        return self.display_string

    def __str__(self):
        return self.display_string


def calculate_preferred_size_in_characters(files: List[DisplayableIFile]) -> Tuple[int, int]:
    width = 0
    height = len(files)
    for file in files:
        display_string = file.get_display_string()
        width = max(width, len(display_string))
    return width + 7, height


def open_files(user_file_choices: List[IFile]):
    if not user_file_choices:
        return  # User cancelled
    for file in user_file_choices:
        IDE().open_editor(page=file)


class EclipseMessageUtils:
    @staticmethod
    def get_workbench_page() -> IWorkbenchPage:
        pass

    @staticmethod
    def show_error_dialog(title: str, message: str) -> None:
        print(f"Error: {title} - {message}")

    @staticmethod
    def force_active():
        pass


class IDE:
    @staticmethod
    def open_editor(page: IWorkbenchPage, file: IFile):
        try:
            page.open_editor(file)
        except PartInitException as e:
            EclipseMessageUtils.show_error_dialog("Unable to Open Script", "Couldn't open editor for {}".format(str(file)))

    @staticmethod
    def get_workbench_window() -> Window:
        pass

    @staticmethod
    def force_active():
        pass


class IFile:
    def __init__(self, file_path: str):
        self.file_path = file_path

    def get_location(self) -> str:
        return self.file_path

    def get_project_relative_path(self) -> Tuple[str]:
        return os.path.relpath(self.file_path)


class IJavaProject:
    pass


class NullProgressMonitor:
    pass
