import json
from flask import Flask, request, jsonify
from werkzeug.exceptions import NotFound, BadRequest

app = Flask(__name__)

class ErrorTestService:
    def null_parameter_query_get(self):
        return "oh oh"

    def null_parameter_query_post(self):
        return "oh oh"

    def empty_parameter_query_get(self, hash: str):
        if not hash:
            raise ValueError("Hash cannot be empty")
        return "oh oh"

    def blank_parameter_query_get(self, hash: str):
        if not hash.strip():
            raise ValueError("Hash must contain at least one character")
        return "oh oh"

    def nessie_not_found(self):
        raise NessieReferenceNotFoundException("not-there-message", Exception("not-there-exception"))

    def basic_entity(self, entity: dict):
        # Assuming SomeEntity is a dictionary
        return json.dumps(entity)

    def constraint_definition_exception(self):
        raise ConstraintDefinitionException("meep")

    def constraint_declaration_exception(self):
        raise ConstraintDeclarationException("meep")

    def group_definition_exception(self):
        raise GroupDefinitionException("meep")

    @app.route('/unhandled_exception_in_tvs_store/<string:exception>')
    def unhandled_exception_in_tvs_store(self, exception: str):
        if exception == "runtime":
            ex = Exception("Store.getValues-throwing")
        elif exception == "throttle":
            ex = BackendLimitExceededException("Store.getValues-throttled")
        else:
            raise ValueError("test code error")

        try:
            database_adapter = DatabaseAdapter()
            named_refs = database_adapter.named_refs()
            for ref in named_refs:
                pass
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        return "we should not get here"


if __name__ == "__main__":
    app.run(debug=True)
