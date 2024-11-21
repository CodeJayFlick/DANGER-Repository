class OffcutReferencesVTPreconditionValidator:
    def __init__(self, source_program: 'Program', destination_program: 'Program',
                 existing_results: 'VTSession'):
        super().__init__(source_program, destination_program, existing_results)

    def create_post_analysis_precondition_validator(self, program: 'Program') -> 'PostAnalysisValidator':
        return OffcutReferencesValidator(program)
