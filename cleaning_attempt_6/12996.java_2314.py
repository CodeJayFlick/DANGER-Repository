import os
from typing import List

class FileSearcherException(Exception):
    pass


def gather_files_from_dir(curr_dir_to_search: str, curr_file_type_ext_list: List[str], use_recursion_in_search: bool) -> List[os.path.join]:
    found_files_from_search_list = []

    if not curr_dir_to_search:
        raise FileSearcherException("The Directory to Search cannot be NULL!")

    elif not os.path.isdir(curr_dir_to_search):
        raise FileSearcherException(f"The Directory must be a valid Directory! It currently is not: {curr_dir_to_search}")

    elif not curr_file_type_ext_list:
        raise FileSearcherException("File Type Extension list is NULL! Must Provide at least 1 File Type Extension to search for!")

    elif len(curr_file_type_ext_list) == 0 or not curr_file_type_ext_list:
        raise FileSearcherException(f"Must Provide at least 1 File Type Extension to search for: {curr_file_type_ext_list}")

    if os.path.isdir(curr_dir_to_search):
        files = [os.path.join(curr_dir_to_search, f) for f in os.listdir(curr_dir_to_search)]
        locate_files_from_dir_root(files, curr_file_type_ext_list, found_files_from_search_list, use_recursion_in_search)

    return found_files_from_search_list


def locate_files_from_dir_root(curr_dir_array: List[str], curr_file_type_ext_list: List[str], curr_files_from_search_list: List[os.path.join], recursive_search: bool):
    for file in curr_dir_array:
        if os.path.isdir(file):
            if recursive_search:
                files = [os.path.join(file, f) for f in os.listdir(file)]
                locate_files_from_dir_root(files, curr_file_type_ext_list, curr_files_from_search_list, recursive_search)
        else:
            for file_type_ext in curr_file_type_ext_list:
                if file.endswith(file_type_ext):
                    curr_files_from_search_list.append(os.path.join(curr_dir_to_search, file))


if __name__ == "__main__":
    # TODO Auto-Generated method stub
