import os
from zipfile import ZipFile
from io import BytesIO

class RestoreTask:
    def __init__(self, project_locator: str, project_archive_file_path: str):
        self.project_locator = project_locator
        self.project_archive_file_path = project_archive_files_path
        # Other attributes as needed

    def run(self) -> None:
        if os.path.exists(self.project_locator.get_project_dir()):
            print("Project already exists at:", self.project_locator.get_project_dir())
            return
        
        with ZipFile(BytesIO(), 'r') as archive_file:
            try:
                for file in archive_file.namelist():
                    # Verify the archive
                    magic_file = next((f for f in archive_file.namelist() if f.lower().startswith(ArchivePlugin.JAR_VERSION_TAG)), None)
                    if not magic_file:
                        raise ValueError("Missing Ghidra Project Archive (.gar) marker file")
                    
                    # Extract files and directories
                    if should_skip(file):
                        continue
                    
                    dest_path = os.path.join(self.project_locator.get_project_dir(), file)
                    with open(dest_path, 'wb') as f:
                        archive_file.extract(file, BytesIO())
            
            except CancelledException:
                print("Restore Archive: Cancellation requested by user.")
            except Exception as e:
                print(f"Restore Archive Failed: {e}")
        
        # Create project marker file
        try:
            with open(self.project_locator.get_marker_file_path(), 'wb') as f:
                pass
        except IOError as e:
            raise ValueError("Couldn't create file " + self.project_locator.get_marker_file_path())
        
        # Open restored project
        print(f"Restore Archive: {self.project_locator} succeeded.")
    
    def should_skip(self, file_name: str) -> bool:
        if file_name.lower() in FILES_TO_SKIP or file_name == ArchivePlugin.OLD_FOLDER_PROPERTIES_FILE:
            return True
        
        ext = os.path.splitext(file_name)[1].lower()
        if GhidraURL.MARKER_FILE_EXTENSION == ext:
            return True
        
        return False

    def create_project_marker_file(self) -> None:
        try:
            with open(self.project_locator.get_marker_file_path(), 'wb') as f:
                pass
        except IOError as e:
            raise ValueError("Couldn't create file " + self.project_locator.get_marker_file_path())

    def verify_archive(self, archive: ZipFile, monitor: TaskMonitor) -> None:
        if not archive.filename.lower().startswith(ArchivePlugin.JAR_VERSION_TAG):
            raise ValueError("Not a zip file")
        
        magic_file = next((f for f in archive.namelist() if f.lower().startswith(ArchivePlugin.JAR_VERSION_TAG)), None)
        if not magic_file:
            raise ValueError("Missing Ghidra Project Archive (.gar) marker file")

    def process_file(self, src_gfile: GFile, dest_fs_file: File, monitor: TaskMonitor) -> None:
        # Process the file
        pass

    def process_directory(self, src_gfile_directory: GFile, dest_directory: File, 
                           monitor: TaskMonitor) -> None:
        # Process the directory
        pass

    def map_source_filename_to_dest(self, src_file: GFile) -> str:
        filename = src_file.name
        if not FSUtilities.get_safe_filename(filename).equals(filename):
            raise ValueError("Bad filename in archive")
        
        return filename

# Usage example
restore_task = RestoreTask(project_locator="path/to/project", project_archive_file_path="path/to/archive.gar")
restore_task.run()
