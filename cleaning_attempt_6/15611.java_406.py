class MRL:
    def __init__(self, repository: 'Repository', type: str, application: 'Application', group_id: str, artifact_id: str, version: str = None, artifact_name: str = None):
        self.repository = repository
        self.type = type
        self.application = application
        self.group_id = group_id
        self.artifact_id = artifact_id
        self.version = version
        self.artifact_name = artifact_name

    @staticmethod
    def model(repository, application, group_id: str, artifact_id: str, version: str = None, artifact_name: str = None):
        return MRL(repository, "model", application, group_id, artifact_id, version, artifact_name)

    @staticmethod
    def dataset(repository, application, group_id: str, artifact_id: str, version: str = None):
        return MRL(repository, "dataset", application, group_id, artifact_id, version, None)

    @staticmethod
    def undefined(repository, group_id: str, artifact_id: str):
        return MRL(repository, "", Application.UNDEFINED, group_id, artifact_id, None, None)

    def to_uri(self) -> 'URI':
        sb = StringBuilder()
        if self.type:
            sb.append(self.type).append('/')
        sb.append(self.application.path).append('/').append(self.group_id.replace('.', '/')).append('/').append(self.artifact_id)
        return URI(sb.toString())

    @property
    def repository(self):
        return self.repository

    @property
    def application(self):
        return self.application

    @property
    def group_id(self):
        return self.group_id

    @property
    def artifact_id(self):
        return self.artifact_id

    @property
    def version(self):
        return self.version

    def get_default_artifact(self) -> 'Artifact':
        return self.repository.resolve(self, None)

    def match(self, criteria: dict) -> 'Artifact':
        artifacts = self.search(criteria)
        if not artifacts:
            return None
        if self.artifact_name is not None:
            for artifact in artifacts:
                if self.artifact_name == artifact.name:
                    return artifact
            return None
        return artifacts[0]

    def list_artifacts(self) -> 'List[Artifact]':
        return self.get_metadata().artifacts

    def prepare(self, artifact: 'Artifact', progress: Progress = None):
        if artifact is not None:
            logger.debug(f"Preparing artifact {self.repository.name}, {artifact}")
            self.repository.prepare(artifact, progress)

    def search(self, criteria: dict) -> 'List[Artifact]':
        return self.get_metadata().search(version_range.parse(self.version), criteria)

    def get_metadata(self):
        if not hasattr(self, '_metadata'):
            metadata = self.repository.locate(self)
            if metadata is None:
                raise IOException(f"Resource {self} not found.")
            setattr(self, '_metadata', metadata)
        return getattr(self, '_metadata')

    def __str__(self) -> str:
        return str(self.to_uri())
