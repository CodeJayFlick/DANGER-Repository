class TsFileTimeGenerator:
    def __init__(self, iexpression, chunk_loader, metadata_querier):
        self.chunk_loader = chunk_loader
        self.metadata_querier = metadata_querier
        
        super().__init__(iexpression)

    @property
    def is_ascending(self):
        return True

    def generate_new_batch_reader(self, expression):
        try:
            chunk_metadata_list = self.metadata_querier.get_chunk_meta_data_list(expression.series_path)
            return FileSeriesReader(self.chunk_loader, chunk_metadata_list, expression.filter)
        except Exception as e:
            raise
