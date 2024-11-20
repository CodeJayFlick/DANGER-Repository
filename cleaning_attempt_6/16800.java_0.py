import os
from typing import Any, Optional

class TsFileOutputFormat(T):
    def __init__(self, path: str, schema: 'Schema', config: 'TSFileConfig') -> None:
        super().__init__(path if path else None)
        self.schema = Preconditions.check_not_none(schema)
        self.config = config

    @property
    def hadoop_conf(self) -> Any:
        return HadoopUtils.get_hadoop_configuration()

    @property
    def writer(self) -> 'TsFileWriter':
        return _writer

    def configure(self, flink_config: dict) -> None:
        super().configure(flink_config)
        self.hadoop_conf = HadoopUtils.get_hadoop_configuration(flink_config)

    def open(self, task_number: int, num_tasks: int) -> None:
        super().open(task_number, num_tasks)
        if self.config is not None:
            TSFileConfigUtil.set_global_tsfile_config(self.config)
        # Use TsFile API to write instead of FSDataOutputStream.
        stream.close()
        actual_file_path = get_actual_file_path()
        out: Any
        try:
            if actual_file_path.startswith('hdfs://'):
                # HDFS
                out = HDFSOutput(os.path.join(actual_file_path, 'path'), self.hadoop_conf)
            else:
                # Local File System
                fos = open(actual_file_path, 'w')
                out = LocalTsFileOutput(fos)
        except URISyntaxException as e:
            raise RuntimeError(e)

    def close(self) -> None:
        super().close()
        try:
            if _writer is not None:
                writer.close()
                _writer = None
        finally:
            if fos is not None:
                fos.close()

    @property
    def schema(self) -> 'Schema':
        return self._schema

    @property
    def config(self) -> Optional['TSFileConfig']:
        return Optional.ofNullable(self.config)

def get_actual_file_path() -> str:
    try:
        field = FileOutputFormat.__dict__['actual_file_path']
        return field.get(self)
    except AttributeError as e:
        raise RuntimeError("Get actual file path failed!", e)

class Schema:  # TODO: implement
    pass

class TSFileConfig:  # TODO: implement
    pass

class TsFileWriter:  # TODO: implement
    def close(self) -> None:
        pass
