class NoProjectNameDockerComposeContainer:
    def __init__(self, identifier, *compose_files):
        super().__init__(identifier, compose_files)
        try:
            project = type(self).getattribute('project')
            setattr(project, self.__dict__, '')
        except AttributeError as e:
            print(f"Error: {e}")
