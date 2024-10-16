import os
import shutil

def organize_by_extension(directory):
    # Check if the provided directory exists
    if not os.path.exists(directory):
        print(f"The directory '{directory}' does not exist.")
        return

    # Loop through each file in the directory
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)

        # Skip directories and only process files
        if os.path.isfile(file_path):
            # Extract file extension
            file_extension = filename.split('.')[-1].lower()
            
            # If no extension, skip the file
            if len(file_extension) == len(filename):
                continue

            # Create a folder for the extension if it doesn't exist
            folder_path = os.path.join(directory, file_extension)
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)

            # Move the file to the folder
            shutil.move(file_path, os.path.join(folder_path, filename))

    print(f"Files in '{directory}' have been organized by extension.")

# Example usage
directory_to_organize = '/Path/To/Directory'
organize_by_extension(directory_to_organize)
