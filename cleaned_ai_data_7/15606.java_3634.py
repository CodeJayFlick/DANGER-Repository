class FilenameUtils:
    def __init__(self):
        pass

    @staticmethod
    def get_file_type(file_name: str) -> str:
        file_name = file_name.lower()
        if file_name.endswith('.zip'):
            return 'zip'
        elif (file_name.endswith('.tgz') or 
              file_name.endswith('.tar.gz') or 
              file_name.endswith('.tar.z')):
            return 'tgz'
        elif file_name.endswith('.tar'):
            return 'tar'
        elif file_name.endswith('.gz') or file_name.endswith('.z'):
            return 'gzip'
        else:
            return ''

    @staticmethod
    def is_archive_file(file_name: str) -> bool:
        file_type = FilenameUtils.get_file_type(file_name)
        return file_type in ['tgz', 'zip', 'tar']

    @staticmethod
    def get_name_part(name: str) -> str:
        lower_case = name.lower()
        if lower_case.endswith('.tar.gz'):
            return name[:-7]
        elif lower_case.endswith('.tar.z'):
            return name[:-6]
        elif (name.endswith('.tgz') or 
              name.endswith('.zip') or 
              name.endswith('.tar')):
            return name[:-4]
        elif name.endswith('.gz'):
            return name[:-3]
        elif name.endswith('.z'):
            return name[:-2]
        else:
            return name

    @staticmethod
    def get_file_extension(file_name: str) -> str:
        pos = file_name.rfind('.')
        if pos > 0:
            return file_name[pos + 1:]
        else:
            return ''
