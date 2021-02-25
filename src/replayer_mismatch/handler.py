import boto3
import os
import json
import argparse
import sys
import socket
import logging

from replayer_mismatch.query_rds import get_connection, get_additional_record_data


def setup_logging(logger_level):
    the_logger = logging.getLogger()
    for old_handler in the_logger.handlers:
        the_logger.removeHandler(old_handler)

    new_handler = logging.StreamHandler(sys.stdout)

    hostname = socket.gethostname()

    json_format = (
        '{ "timestamp": "%(asctime)s", "log_level": "%(levelname)s", "message": "%(message)s", '
        f'"environment": "{args.environment}", "application": "{args.application}", '
        f'"module": "%(module)s", "process": "%(process)s", '
        f'"thread": "[%(thread)s]", "hostname": "{hostname}" }} '
    )

    new_handler.setFormatter(logging.Formatter(json_format))
    the_logger.addHandler(new_handler)
    new_level = logging.getLevelName(logger_level.upper())
    the_logger.setLevel(new_level)

    if the_logger.isEnabledFor(logging.DEBUG):
        boto3.set_stream_logger()
        the_logger.debug(f'Using boto3", "version": "{boto3.__version__}')

    return the_logger


def get_parameters():
    parser = argparse.ArgumentParser(
        description="An AWS lambda which receives payload information of replayed mismatch records, "
        "and fetches additional information from both databases before recording in DynamoDb."
    )

    # Parse command line inputs and set defaults
    parser.add_argument("--aws-region")
    parser.add_argument("--environment", default="NOT_SET")
    parser.add_argument("--application", default="NOT_SET")
    parser.add_argument("--log-level", default="INFO")

    _args = parser.parse_args()

    # Override arguments with environment variables where set
    if "AWS_REGION" in os.environ:
        _args.aws_region = os.environ["AWS_REGION"]

    if "ENVIRONMENT" in os.environ:
        _args.environment = os.environ["ENVIRONMENT"]

    if "APPLICATION" in os.environ:
        _args.application = os.environ["APPLICATION"]

    if "LOG_LEVEL" in os.environ:
        _args.log_level = os.environ["LOG_LEVEL"]

    required_args = ["log_level"]

    missing_args = []
    for required_message_key in required_args:
        if required_message_key not in _args:
            missing_args.append(required_message_key)
    if missing_args:
        raise argparse.ArgumentError(
            None,
            "ArgumentError: The following required arguments are missing: {}".format(
                ", ".join(missing_args)
            ),
        )

    return _args


def get_parameter_store_value(parameter_name, region):
    ssm = boto3.client("ssm", region_name=region)

    try:
        parameter = ssm.get_parameter(
            Name=parameter_name, WithDecryption=False
        )
        return parameter
    except Exception as e:
        logger.error(f'Error attempting to retrieve parameter", "parameter_name": "{parameter_name}", '
                     f'"request_region": "{region}", "exception": "{e}')
        raise e


def dynamo_db_format(
        nino: str, transaction_id: str, take_home_pay: str, ireland_additional_data: dict, london_additional_data: dict
):
    return {
        'nino': nino,
        'transaction_id': transaction_id,
        'decrypted_take_home_pay': take_home_pay,

        "contract_id_ire": ireland_additional_data["contractId"],
        "contract_id_ldn": london_additional_data["contractId"],

        "ap_start_date_ire": ireland_additional_data["apStartDate"],
        "ap_end_date_ire": ireland_additional_data["apEndDate"],

        "ap_start_date_ldn": london_additional_data["apStartDate"],
        "ap_end_date_ldn": london_additional_data["apEndDate"],

        "suspension_date_ire": ireland_additional_data["suspensionDate"],
        "suspension_date_ldn": london_additional_data["suspensionDate"],

        "statement_created_date_ire": ireland_additional_data["statementCreatedDate"],
        "statement_created_date_ldn": london_additional_data["statementCreatedDate"]
    }


args = None
logger = None


def handler(event, context):
    global args
    args = get_parameters()
    global logger
    logger = setup_logging(args.log_level)

    logger.info(f"Event: {event}")

    nino = json.loads(event["nino"])
    transaction_id = json.loads(event["transaction_id"])
    take_home_pay = json.loads(event["take_home_pay"])

    logger.info(
        f'Requesting additional data for unmatched record", "nino": "{nino}", "transaction_id": "{transaction_id}')

    ireland_sql_password = get_parameter_store_value(args.ireland_master_pw_parameter, "eu-west-1")
    ireland_connection = get_connection(
        args.ireland_rds_hostname,
        args.ireland_rds_username,
        ireland_sql_password,
        args.ireland_database_name,
        args.use_ssl
    )
    # TODO: Figure out how to handle if multiple records are returned
    ireland_additional_data = get_additional_record_data(
        nino,
        ireland_connection
    )

    london_sql_password = get_parameter_store_value(args.ireland_master_pw_parameter, "eu-west-2")
    london_connection = get_connection(
        args.london_rds_hostname,
        args.london_rds_username,
        london_sql_password,
        args.london_database_name,
        args.use_ssl
    )
    # TODO: Figure out how to handle if multiple records are returned
    london_additional_data = get_additional_record_data(
        nino,
        london_connection
    )

    try:
        dynamodb_data = dynamo_db_format(
            nino, transaction_id, take_home_pay, ireland_additional_data, london_additional_data
        )

        ddb = boto3.client("dynamodb")
        table = ddb.Table(args.ddb_record_mismatch_table)

        dynamodb_record_mismatch_record(table, dynamodb_data)
    except KeyError as e:
        logger.error('Error attempting to build dynamoDB data", '
                     f'"ireland_additional_data": "{ireland_additional_data}", "missing_key": "{e.args[0]}",'
                     f'"london_additional_data": "{london_additional_data}", "exception": "{e}')

    except Exception as e:
        logger.error('Error attempting to put dynamoDB record", '
                     f'"dynamodb_data": "{dynamodb_data}", "table_name": "{table.name}", "exception": "{e}')


def dynamodb_record_mismatch_record(ddb_table, data):
    logger.info(
        f'Recording mismatch record into DynamoDB", "ddb_record_mismatch_table": "{ddb_table.name}", '
        f'"nino": {data["nino"]}'
    )

    response = ddb_table.put_item(Item=data)

    logger.info(f'Recorded mismatch record into DynamoDB, Response: {response}')


if __name__ == "__main__":
    try:
        args = get_parameters()
        logger = setup_logging("INFO")

        boto3.setup_default_session(
            profile_name=args.aws_profile, region_name=args.aws_region
        )
        logger.info(os.getcwd())
        json_content = json.loads(open("../../resources/event.json", "r").read())
        handler(json_content, None)
    except Exception as err:
        logger.error(f'Exception occurred for invocation", "error_message": "{err}')
