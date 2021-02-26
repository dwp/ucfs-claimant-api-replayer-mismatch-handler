import unittest
from unittest.mock import MagicMock

import boto3
from moto import mock_ssm, mock_dynamodb2

import replayer_mismatch.handler
from replayer_mismatch.handler import (
    get_parameter_store_value,
    dynamodb_format,
    dynamodb_record_mismatch_record,
    get_matches
)

replayer_mismatch.handler.logger = MagicMock()

"""Tests for the UCFS claimant API replayer mismatch handler lambda."""

dynamo_data = {
    "nino": "123",
    "statement_id": "123_ire",
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

dynamo_attr_keys = [
    "nino",
    "statement_id",
    "ap_end_date_ire",
    "ap_end_date_ldn",
    "ap_start_date_ire",
    "ap_start_date_ldn",
    "contract_id_ire",
    "contract_id_ldn",
    "decrypted_take_home_pay",
    "statement_created_date_ire",
    "statement_created_date_ldn",
    "suspension_date_ire",
    "suspension_date_ldn",
]


class TestHandler(unittest.TestCase):
    @mock_ssm
    def test_get_parameter_store_value(self):
        ssm = boto3.client("ssm", region_name="eu-west-1")

        ssm.put_parameter(Name="test_param", Value="test_value", Type="String")

        param = get_parameter_store_value("test_param", "eu-west-1")

        assert param == "test_value", f'Expected: "test_param", Got: "{param}"'

    def test_dynamodb_format(self):
        expected = {
            "nino": "123",
            "statement_id": "123_ire",
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

        actual = dynamodb_format(
            "123",
            "123",
            {
                "statementId": "123_ire",
                "contractId": "123_ire",
                "apStartDate": "123_ire",
                "apEndDate": "123_ire",
                "suspensionDate": "123_ire",
                "statementCreatedDate": "123_ire",
            },
            {
                "contractId": "123_ldn",
                "apStartDate": "123_ldn",
                "apEndDate": "123_ldn",
                "suspensionDate": "123_ldn",
                "statementCreatedDate": "123_ldn",
            },
        )

        assert actual == dynamo_data, f'Expected: "{expected}", Got: {actual}'

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

    def test_get_matches(self):
        expected_matches = [
            {'ire': {'nino': '123', 'statement_id': '123'}, 'ldn': {'nino': '123', 'statement_id': '123'}},
            {'ire': {'nino': '321', 'statement_id': '321'}, 'ldn': {'nino': '321', 'statement_id': '321'}},
        ]
        expected_non_matches = [
            {'ire': {'nino': '1234', 'statement_id': '1234'}, 'ldn': {}},
            {'ire': {}, 'ldn': {'nino': '4321', 'statement_id': '4321'}},
        ]

        actual_matches, actual_non_matches = get_matches(
            [
                {'nino': '123', 'statement_id': '123'},
                {'nino': '321', 'statement_id': '321'},
                {'nino': '1234', 'statement_id': '1234'},
            ],
            [
                {'nino': '123', 'statement_id': '123'},
                {'nino': '321', 'statement_id': '321'},
                {'nino': '4321', 'statement_id': '4321'},
            ],
        )

        assert actual_matches == expected_matches, f'Expected: "{expected_matches}", Got: "{actual_matches}"'
        assert actual_non_matches == expected_non_matches, f'Expected: "{expected_non_matches}", Got: "{actual_non_matches}"'
