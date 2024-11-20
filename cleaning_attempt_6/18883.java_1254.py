import requests
from datetime import datetime as dt
from unittest.mock import patch

class AbstractResteasyTest:
    BASE_PATH = "/api/v1/"

    @classmethod
    def enable_logging(cls):
        RestAssured.enable_logging_of_request_and_response_if_validation_fails()

    @patch('requests.Session')
    def test_basic(self, session_mock):
        pre_size = requests.get(f"{self.BASE_PATH}trees").json()["references"].length

        requests.post(f"{self.BASE_PATH}trees/tree", json={"name": "mainx"}).status_code == 200
        reference = requests.get(f"{self.BASE_PATH}trees/tree/mainx").json()
        self.assertEqual("mainx", reference["name"])

        new_reference = {"hash": reference["hash"], "name": "test"}
        response = requests.post(
            f"{self.BASE_PATH}trees/tree",
            json={"expectedHash": reference["hash"]},
            body=Branch.of("test", None)
        ).json()
        self.assertEqual(new_reference, response)

        table = {"path": "/the/directory/over/there", "format": "x"}
        commit_response = requests.post(
            f"{self.BASE_PATH}trees/tree/{new_reference['name']}/commit",
            json={"expectedHash": new_reference["hash"]},
            body=ImmutableOperations.builder().add_operations([
                ImmutablePut.builder()
                    .key(ContentsKey.of("xxx", "test"))
                    .contents(IcebergTable.of(table, "x"))  # This line is not clear
                    .build()]).commit_meta(CommitMeta.from_message(""))).json()

        self.assertNotEqual(new_reference["hash"], commit_response["hash"])

    def rest(self):
        return requests.Session().get(f"{self.BASE_PATH}", headers={"Content-Type": "application/json"})

    @classmethod
    def commit(cls, contents_id, branch, contents_key, metadata_url, author=None, expected_metadata_url=None):
        operations = ImmutableOperations.builder()
        if expected_metadata_url:
            operations.add_operations([
                Put.of(
                    ContentsKey.of(contents_key),
                    IcebergTable.of(metadata_url, "x", contents_id),
                    IcebergTable.of(expected_metadata_url, "x", contents_id)
                )
            ])
        else:
            operations.add_operations([Put.of(ContentsKey.of(contents_key), IcebergTable.of(metadata_url, "x", contents_id))])
        return requests.post(
            f"{self.BASE_PATH}trees/branch/{branch}/commit",
            json={"expectedHash": branch["hash"]},
            body=operations.commit_meta(CommitMeta.builder().author(author).message("").build())
        ).json()

    @classmethod
    def get_branch(cls, name):
        return requests.get(f"{self.BASE_PATH}trees/tree/{name}").json()

    @classmethod
    def make_branch(cls, name):
        test = {"name": name}
        response = requests.post(self.BASE_PATH + "trees/tree", json=test).json()
        self.assertEqual(test["name"], response)
        return test

    # More tests...

if __name__ == "__main__":
    AbstractResteasyTest().test_basic()

