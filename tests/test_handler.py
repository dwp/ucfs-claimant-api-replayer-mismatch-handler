import unittest
from argparse import Namespace
from unittest import mock
from unittest.mock import MagicMock, ANY

import boto3
from botocore.exceptions import ParamValidationError, ClientError
from moto import mock_ssm, mock_dynamodb2, mock_kms

import replayer_mismatch.handler
from replayer_mismatch.handler import (
    get_parameter_store_value,
    dynamodb_format,
    dynamodb_record_mismatch_record,
    get_matches,
    handler,
)

replayer_mismatch.handler.logger = MagicMock()

"""Tests for the UCFS claimant API replayer mismatch handler lambda."""

dynamo_data = {
    "nino": "123",
    "statement_id": "123_ire",
    "recorded_datetime": "2020-12-25T07:00:00",
    "decrypted_take_home_pay": "123",
    "contract_id_ire": "123_ire",
    "contract_id_ldn": "123_ldn",
    "ap_start_date_ire": "123_ire",
    "ap_end_date_ire": "123_ire",
    "ap_start_date_ldn": "123_ldn",
    "ap_end_date_ldn": "123_ldn",
    "suspension_date_ire": "123_ire",
    "suspension_date_ldn": "123_ldn",
    "statement_created_date_ire": "123_ire",
    "statement_created_date_ldn": "123_ldn",
}

mock_params = Namespace()
mock_params.__dict__ = {
    "aws_region": "eu-west-1",
    "application": "ucfs-claimant-api-replayer-mismatch-handler",
    "ddb_record_mismatch_table": "mismatch-table",
    "environment": "test",
    "ireland_database_name": "ireDB",
    "ireland_parameter_region": "eu-west-1",
    "ireland_rds_hostname": "ireDB.test",
    "ireland_rds_parameter": "test_ire_rds_param",
    "ireland_rds_username": "testUser",
    "log_level": "INFO",
    "london_database_name": "ldnDB",
    "london_parameter_region": "eu-west-2",
    "london_rds_hostname": "ldnDB.test",
    "london_rds_parameter": "test_ldn_rds_param",
    "london_rds_username": "testUser",
    "use_ssl": "true",
}

additional_record_data = {
    "nino": "123",
    "statementId": "123",
    "contract_id": "123",
    "apStartDate": "123",
    "apEndDate": "123",
    "suspensionDate": "123",
    "statementCreatedDate": "123",
    "take_home_pay": "123.45",
}


def handle_mock_get_connection(hostname, *_):
    return "mock_connection_ire" if "ire" in hostname.lower() else "mock_connection_ldn"


def handle_mock_additional_record_data_matches(_, connection, __):
    suffix = "ire" if "ire" in connection else "ldn"
    ret = {}
    for k, v in additional_record_data.items():
        if k in ["nino", "statementId"]:
            ret[k] = v

        else:
            ret[k] = f"{v}_{suffix}"

    return [ret]


def handle_mock_additional_record_data_non_matches(_, connection, __):
    suffix = "ire" if "ire" in connection else "ldn"
    return [{k: f"{v}_{suffix}" for k, v in additional_record_data.items()}]


class TestHandler(unittest.TestCase):
    @mock_ssm
    @mock_dynamodb2
    def test_handler_non_matches(self):
        ssm = boto3.client("ssm", region_name="eu-west-1")
        ssm.put_parameter(Name="test_ire_rds_param", Value="test_value", Type="String")
        ssm = boto3.client("ssm", region_name="eu-west-2")
        ssm.put_parameter(Name="test_ldn_rds_param", Value="test_value", Type="String")

        boto3.client("dynamodb", region_name="eu-west-1").create_table(
            TableName="mismatch-table",
            KeySchema=[
                {"AttributeName": "nino", "KeyType": "HASH"},  # Partition key
                {"AttributeName": "statement_id", "KeyType": "RANGE"},  # Sort key
            ],
            AttributeDefinitions=[
                {"AttributeName": "nino", "AttributeType": "S"},
                {"AttributeName": "statement_id", "AttributeType": "S"},
            ],
            ProvisionedThroughput={"ReadCapacityUnits": 10, "WriteCapacityUnits": 10},
        )

        with mock.patch(
            "replayer_mismatch.handler.get_parameters"
        ) as mock_get_parameters, mock.patch(
            "replayer_mismatch.handler.get_connection"
        ) as mock_get_connection, mock.patch(
            "replayer_mismatch.handler.get_additional_record_data"
        ) as mock_get_additional_record_data, mock.patch(
            "replayer_mismatch.handler.get_date_time"
        ) as mock_datetime:
            mock_get_parameters.return_value = mock_params
            mock_get_connection.side_effect = handle_mock_get_connection
            mock_get_additional_record_data.side_effect = (
                handle_mock_additional_record_data_non_matches
            )
            mock_datetime.return_value = "2020-01-25T19:30:00"

            handler(
                {"nino": "123", "transaction_id": "42", "take_home_pay": "123.45"}, None
            )

            mock_get_connection.assert_has_calls(
                [
                    mock.call(
                        "ireDB.test",
                        "testUser",
                        "test_value",
                        "ireDB",
                        "true",
                        replayer_mismatch.handler.logger,
                    ),
                    mock.call(
                        "ldnDB.test",
                        "testUser",
                        "test_value",
                        "ldnDB",
                        "true",
                        replayer_mismatch.handler.logger,
                    ),
                ]
            )

            mock_get_additional_record_data.assert_has_calls(
                [
                    mock.call("123", "mock_connection_ire", ANY),
                    mock.call("123", "mock_connection_ldn", ANY),
                ]
            )

            ddb_table = boto3.resource("dynamodb", "eu-west-1").Table("mismatch-table")

            expected = {
                "nino": "123",
                "statement_id": "123_ire",
                "recorded_datetime": "2020-01-25T19:30:00",
                "decrypted_take_home_pay": "123.45",
                "contract_id_ire": "123_ire",
                "contract_id_ldn": "",
                "ap_start_date_ire": "123_ire",
                "ap_end_date_ire": "123_ire",
                "ap_start_date_ldn": "",
                "ap_end_date_ldn": "",
                "suspension_date_ire": "123_ire",
                "suspension_date_ldn": "",
                "statement_created_date_ire": "123_ire",
                "statement_created_date_ldn": "",
                "thp_ire": "123.45_ire",
                "thp_ldn": "",
            }

            actual = ddb_table.get_item(Key={"nino": "123", "statement_id": "123_ire"})[
                "Item"
            ]

            assert actual == expected

    @mock_ssm
    @mock_dynamodb2
    def test_handler_matches(self):
        ssm = boto3.client("ssm", region_name="eu-west-1")
        ssm.put_parameter(Name="test_ire_rds_param", Value="test_value", Type="String")
        ssm = boto3.client("ssm", region_name="eu-west-2")
        ssm.put_parameter(Name="test_ldn_rds_param", Value="test_value", Type="String")

        boto3.client("dynamodb", region_name="eu-west-1").create_table(
            TableName="mismatch-table",
            KeySchema=[
                {"AttributeName": "nino", "KeyType": "HASH"},  # Partition key
                {"AttributeName": "statement_id", "KeyType": "RANGE"},  # Sort key
            ],
            AttributeDefinitions=[
                {"AttributeName": "nino", "AttributeType": "S"},
                {"AttributeName": "statement_id", "AttributeType": "S"},
            ],
            ProvisionedThroughput={"ReadCapacityUnits": 10, "WriteCapacityUnits": 10},
        )

        with mock.patch(
            "replayer_mismatch.handler.get_parameters"
        ) as mock_get_parameters, mock.patch(
            "replayer_mismatch.handler.get_connection"
        ) as mock_get_connection, mock.patch(
            "replayer_mismatch.handler.get_additional_record_data"
        ) as mock_get_additional_record_data, mock.patch(
            "replayer_mismatch.handler.get_date_time"
        ) as mock_datetime:
            mock_get_parameters.return_value = mock_params
            mock_get_connection.side_effect = handle_mock_get_connection
            mock_get_additional_record_data.side_effect = (
                handle_mock_additional_record_data_matches
            )
            mock_datetime.return_value = "2020-12-25T09:30:00"

            handler(
                {"nino": "123", "transaction_id": "42", "take_home_pay": "123.45"}, None
            )

            mock_get_connection.assert_has_calls(
                [
                    mock.call(
                        "ireDB.test",
                        "testUser",
                        "test_value",
                        "ireDB",
                        "true",
                        replayer_mismatch.handler.logger,
                    ),
                    mock.call(
                        "ldnDB.test",
                        "testUser",
                        "test_value",
                        "ldnDB",
                        "true",
                        replayer_mismatch.handler.logger,
                    ),
                ]
            )

            mock_get_additional_record_data.assert_has_calls(
                [
                    mock.call("123", "mock_connection_ire", ANY),
                    mock.call("123", "mock_connection_ldn", ANY),
                ]
            )

            ddb_table = boto3.resource("dynamodb", "eu-west-1").Table("mismatch-table")

            expected = {
                "nino": "123",
                "statement_id": "123",
                "recorded_datetime": "2020-12-25T09:30:00",
                "decrypted_take_home_pay": "123.45",
                "contract_id_ire": "123_ire",
                "contract_id_ldn": "123_ldn",
                "ap_start_date_ire": "123_ire",
                "ap_end_date_ire": "123_ire",
                "ap_start_date_ldn": "123_ldn",
                "ap_end_date_ldn": "123_ldn",
                "suspension_date_ire": "123_ire",
                "suspension_date_ldn": "123_ldn",
                "statement_created_date_ire": "123_ire",
                "statement_created_date_ldn": "123_ldn",
                "thp_ire": "123.45_ire",
                "thp_ldn": "123.45_ldn",
            }

            actual = ddb_table.get_item(Key={"nino": "123", "statement_id": "123"})[
                "Item"
            ]

            assert expected == actual

    @mock_ssm
    def test_get_parameter_store_value(self):
        ssm = boto3.client("ssm", region_name="eu-west-1")

        ssm.put_parameter(Name="test_param", Value="test_value", Type="String")

        param = get_parameter_store_value("test_param", "eu-west-1")

        assert param == "test_value", f'Expected: "test_param", Got: "{param}"'

    @mock_ssm
    def test_get_parameter_store_value_exception(self):
        with self.assertRaises(ClientError):
            get_parameter_store_value("test_param", "eu-west-1")

        with self.assertRaises(ParamValidationError):
            get_parameter_store_value(b"test_param", "eu-west-1")

    def test_dynamodb_format_uses_ireland_statement_id_if_present(self):
        with mock.patch("replayer_mismatch.handler.get_date_time") as mock_datetime:
            mock_datetime.return_value = "2021-03-05T17:42:21"

            expected = {
                "nino": "123",
                "statement_id": "123_ire",
                "recorded_datetime": "2021-03-05T17:42:21",
                "decrypted_take_home_pay": "123",
                "contract_id_ire": "123_ire",
                "contract_id_ldn": "123_ldn",
                "ap_start_date_ire": "123_ire",
                "ap_end_date_ire": "123_ire",
                "ap_start_date_ldn": "123_ldn",
                "ap_end_date_ldn": "123_ldn",
                "suspension_date_ire": "123_ire",
                "suspension_date_ldn": "123_ldn",
                "statement_created_date_ire": "123_ire",
                "statement_created_date_ldn": "123_ldn",
                "thp_ire": "123.45_ire",
                "thp_ldn": "123.45_ldn",
            }

            nino = "123"
            take_home_pay = "123"
            ireland_additional_data = {
                "statementId": "123_ire".encode(),
                "contract_id": "123_ire".encode(),
                "apStartDate": "123_ire".encode(),
                "apEndDate": "123_ire".encode(),
                "suspensionDate": "123_ire".encode(),
                "statementCreatedDate": "123_ire",
                "take_home_pay": "123.45_ire",
            }

            london_additional_data = {
                "statementId": "123_ldn".encode(),
                "contract_id": "123_ldn".encode(),
                "apStartDate": "123_ldn".encode(),
                "apEndDate": "123_ldn".encode(),
                "suspensionDate": "123_ldn".encode(),
                "statementCreatedDate": "123_ldn",
                "take_home_pay": "123.45_ldn",
            }

            actual = dynamodb_format(
                nino, take_home_pay, ireland_additional_data, london_additional_data
            )
            assert actual == expected, f'Expected: "{expected}",\n Got: {actual}'

    def test_dynamodb_format_uses_london_statement_id_if_ireland_missing(self):
        with mock.patch("replayer_mismatch.handler.get_date_time") as mock_datetime:
            mock_datetime.return_value = "2021-03-03T13:00:00"
            expected = {
                "nino": "123",
                "statement_id": "123_ldn",
                "recorded_datetime": "2021-03-03T13:00:00",
                "decrypted_take_home_pay": "123",
                "contract_id_ire": "123_ire",
                "contract_id_ldn": "123_ldn",
                "ap_start_date_ire": "123_ire",
                "ap_end_date_ire": "123_ire",
                "ap_start_date_ldn": "123_ldn",
                "ap_end_date_ldn": "123_ldn",
                "suspension_date_ire": "123_ire",
                "suspension_date_ldn": "123_ldn",
                "statement_created_date_ire": "123_ire",
                "statement_created_date_ldn": "123_ldn",
                "thp_ire": "123.45_ire",
                "thp_ldn": "123.45_ldn",
            }

            nino = "123"
            take_home_pay = "123"
            ireland_additional_data = {
                "contract_id": "123_ire".encode(),
                "apStartDate": "123_ire".encode(),
                "apEndDate": "123_ire".encode(),
                "suspensionDate": "123_ire".encode(),
                "statementCreatedDate": "123_ire".encode(),
                "take_home_pay": "123.45_ire",
            }

            london_additional_data = {
                "statementId": "123_ldn".encode(),
                "contract_id": "123_ldn".encode(),
                "apStartDate": "123_ldn".encode(),
                "apEndDate": "123_ldn".encode(),
                "suspensionDate": "123_ldn".encode(),
                "statementCreatedDate": "123_ldn".encode(),
                "take_home_pay": "123.45_ldn",
            }

            actual = dynamodb_format(
                nino, take_home_pay, ireland_additional_data, london_additional_data
            )

            assert actual == expected, f'Expected: "{expected}",\n Got: {actual}'

    def test_dynamodb_format_sets_na_flag_with_time_for_statement_id_if_missing_from_both(
        self,
    ):
        with mock.patch("replayer_mismatch.handler.get_date_time") as mock_datetime:
            mock_datetime.return_value = "2021-03-05T18:00:00"

            nino = "123"
            take_home_pay = "123"
            ireland_additional_data = {
                "contract_id": "123_ire".encode(),
                "apStartDate": "123_ire".encode(),
                "apEndDate": "123_ire".encode(),
                "suspensionDate": "123_ire".encode(),
                "statementCreatedDate": "123_ire".encode(),
            }

            london_additional_data = {
                "contract_id": "123_ldn".encode(),
                "apStartDate": "123_ldn".encode(),
                "apEndDate": "123_ldn".encode(),
                "suspensionDate": "123_ldn".encode(),
                "statementCreatedDate": "123_ldn".encode(),
            }

            result = dynamodb_format(
                nino, take_home_pay, ireland_additional_data, london_additional_data
            )

            assert result["statement_id"] == "null_2021-03-05T18:00:00"

    @mock_dynamodb2
    def test_dynamodb_record_mismatch_record(self):
        boto3.client("dynamodb", region_name="eu-west-1").create_table(
            TableName="test_table",
            KeySchema=[
                {"AttributeName": "nino", "KeyType": "HASH"},  # Partition key
                {"AttributeName": "statement_id", "KeyType": "RANGE"},  # Sort key
            ],
            AttributeDefinitions=[
                {"AttributeName": "nino", "AttributeType": "S"},
                {"AttributeName": "statement_id", "AttributeType": "S"},
            ],
            ProvisionedThroughput={"ReadCapacityUnits": 10, "WriteCapacityUnits": 10},
        )

        try:
            table = boto3.resource("dynamodb", region_name="eu-west-1").Table(
                "test_table"
            )
            dynamodb_record_mismatch_record(table, dynamo_data)

            item = table.get_item(
                Key={
                    "nino": "123",
                    "statement_id": "123_ire",
                }
            )["Item"]

            assert (
                item["recorded_datetime"] == "2020-12-25T07:00:00"
            ), f'Expected : "2020-12-25T07:00:00", Got: {item["recorded_datetime"]}'
            assert (
                item["ap_start_date_ire"] == "123_ire"
            ), f'Expected : "123_ire", Got: {item["ap_start_date_ire"]}'
            assert (
                item["ap_end_date_ire"] == "123_ire"
            ), f'Expected : "123_ire", Got: {item["ap_end_date_ire"]}'
            assert (
                item["ap_start_date_ldn"] == "123_ldn"
            ), f'Expected : "123_ldn", Got: {item["ap_start_date_ldn"]}'
            assert (
                item["ap_end_date_ldn"] == "123_ldn"
            ), f'Expected : "123_ldn", Got: {item["ap_end_date_ldn"]}'

        except Exception as e:
            self.fail(e)

    @mock_dynamodb2
    def test_dynamodb_record_mismatch_record_exception(self):
        with self.assertRaises(Exception):
            table = MagicMock()
            table.put_item.side_effect = Exception("dummy exception")

            dynamodb_record_mismatch_record(table, dynamo_data)

    def test_get_matches(self):
        expected_matches = [
            {
                "ire": {"nino": "123", "statementId": "123"},
                "ldn": {"nino": "123", "statementId": "123"},
            },
            {
                "ire": {"nino": "321", "statementId": "321"},
                "ldn": {"nino": "321", "statementId": "321"},
            },
        ]
        expected_non_matches = [
            {"ire": {"nino": "1234", "statementId": "1234"}, "ldn": {}},
            {"ire": {}, "ldn": {"nino": "4321", "statementId": "4321"}},
        ]

        actual_matches, actual_non_matches = get_matches(
            [
                {"nino": "123", "statementId": "123"},
                {"nino": "321", "statementId": "321"},
                {"nino": "1234", "statementId": "1234"},
            ],
            [
                {"nino": "123", "statementId": "123"},
                {"nino": "321", "statementId": "321"},
                {"nino": "4321", "statementId": "4321"},
            ],
        )

        assert (
            actual_matches == expected_matches
        ), f'Expected: "{expected_matches}", Got: "{actual_matches}"'
        assert (
            actual_non_matches == expected_non_matches
        ), f'Expected: "{expected_non_matches}", Got: "{actual_non_matches}"'

    def test_get_matches_missing_nino(self):
        with self.assertRaises(KeyError):
            get_matches(
                [
                    {"statementId": "123"},
                ],
                [
                    {"statementId": "123"},
                ],
            )

    def test_get_matches_missing_statement_id(self):
        matches, non_matches = get_matches(
            [
                {"nino": "123"},
                {"nino": "345"},
            ],
            [
                {"nino": "123"},
            ],
        )

        assert matches == [{"ire": {"nino": "123"}, "ldn": {"nino": "123"}}]
        assert non_matches == [{"ire": {"nino": "345"}, "ldn": {}}]
