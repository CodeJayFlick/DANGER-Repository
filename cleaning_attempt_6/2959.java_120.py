import os

class PopulateBigRepoScript:
    def __init__(self):
        self.TEST_BINARY = "/tmp/helloWorld"

    def run(self):
        project_data = state.get_project().get_project_data()
        first_file = get_first_file(project_data)

        for i in range(1, 200000):
            path = get_folder_path(i)
            root_folder = project_data.get_root_folder()
            split_path = path.split("/")
            folder = root_folder
            for n in range(len(split_path) - 1):
                subfolder = os.path.join(folder.name, split_path[n])
                if not os.path.exists(subfolder):
                    os.makedirs(subfolder)
                folder = subfolder

            name = get_name(i)

            if not os.path.exists(os.path.join(folder, name)):
                new_file = first_file.copy_to(folder, monitor=True)
                new_file.rename(name)
                print(f"File: {i} - {new_file.name}")

    def get_first_file(self, project_data):
        folder = project_data.get_folder(get_folder_path(0))
        name = get_name(0)

        file = os.path.join(folder, name)
        if not os.path.exists(file):
            p = import_file(self.TEST_BINARY)
            try:
                df = os.path.join(folder, "df" + str(p).zfill(5) + ".bin")
                open(df, 'wb').write(p.get_bytes())
            finally:
                p.release()

        return file

    def get_path(self, counter):
        if counter == 0:
            return [0]

        path = []
        while counter != 0:
            n = counter % 10
            counter //= 10
            path.append(n)

        return list(reversed(path))

    def get_name(self, counter):
        path = self.get_path(counter)
        name = "df" + "".join(map(str, path)) + ".bin"
        return name

    def get_folder_path(self, counter):
        path = self.get_path(counter)
        buf = "/".join(map(str, path[:-1])) + "/"
        return buf
