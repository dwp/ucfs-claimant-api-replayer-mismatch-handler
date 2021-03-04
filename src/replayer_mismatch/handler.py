import argparse
import json
import logging
import os
import socket
import sys
from typing import List, Union

import boto3

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
    parser.add_argument("--use-ssl", default="true")

    parser.add_argument("--ireland-rds-hostname")
    parser.add_argument("--ireland-rds-username")
    parser.add_argument("--ireland-database-name")

    parser.add_argument("--london-rds-hostname")
    parser.add_argument("--london-rds-username")
    parser.add_argument("--london-database-name")

    parser.add_argument("--ddb-record-mismatch-table")

    parser.add_argument("--ireland-parameter-region")
    parser.add_argument("--london-parameter-region")

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

    if "USE_SSL" in os.environ:
        _args.use_ssl = os.environ["USE_SSL"]

    if "IRELAND_RDS_HOSTNAME" in os.environ:
        _args.ireland_rds_hostname = os.environ["IRELAND_RDS_HOSTNAME"]

    if "IRELAND_RDS_USERNAME" in os.environ:
        _args.ireland_rds_username = os.environ["IRELAND_RDS_USERNAME"]

    if "IRELAND_RDS_PARAMETER" in os.environ:
        _args.ireland_rds_parameter = os.environ["IRELAND_RDS_PARAMETER"]

    if "IRELAND_DATABASE_NAME" in os.environ:
        _args.ireland_database_name = os.environ["IRELAND_DATABASE_NAME"]

    if "LONDON_RDS_HOSTNAME" in os.environ:
        _args.london_rds_hostname = os.environ["LONDON_RDS_HOSTNAME"]

    if "LONDON_RDS_USERNAME" in os.environ:
        _args.london_rds_username = os.environ["LONDON_RDS_USERNAME"]

    if "LONDON_RDS_PARAMETER" in os.environ:
        _args.london_rds_parameter = os.environ["LONDON_RDS_PARAMETER"]

    if "LONDON_DATABASE_NAME" in os.environ:
        _args.london_database_name = os.environ["LONDON_DATABASE_NAME"]

    if "DDB_RECORD_MISMATCH_TABLE" in os.environ:
        _args.ddb_record_mismatch_table = os.environ["DDB_RECORD_MISMATCH_TABLE"]

    if "IRELAND_PARAMETER_REGION" in os.environ:
        _args.ireland_parameter_region = os.environ["IRELAND_PARAMETER_REGION"].lower()

    if "LONDON_PARAMETER_REGION" in os.environ:
        _args.london_parameter_region = os.environ["LONDON_PARAMETER_REGION"].lower()

    required_args = [
        "aws_region",
        "environment",
        "application",
        "log_level",
        "ireland_rds_hostname",
        "ireland_rds_username",
        "ireland_rds_parameter",
        "ireland_database_name",
        "london_rds_hostname",
        "london_rds_username",
        "london_rds_parameter",
        "london_database_name",
        "ddb_record_mismatch_table",
        "ireland_parameter_region",
        "london_parameter_region",
    ]

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
        logger.info(
            f'Attempting to fetch parameter", "parameter_name": "{parameter_name}'
        )
        parameter = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
        return parameter["Parameter"]["Value"]
    except Exception as e:
        logger.error(
            f'Error attempting to retrieve parameter", "parameter_name": "{parameter_name}", '
            f'"request_region": "{region}", "exception": "{e}'
        )
        raise e


def dynamodb_format(
    nino: str,
    take_home_pay: str,
    ireland_additional_data: dict,
    london_additional_data: dict,
):
    if ireland_additional_data.get("statementId", None) is not None:
        statement_id = ireland_additional_data["statementId"]
    else:
        statement_id = london_additional_data["statementId"]

    statement_id = _handle_type(statement_id)

    contract_id_ire = _handle_type(ireland_additional_data.get("contractId", ""))
    contract_id_ldn = _handle_type(london_additional_data.get("contractId", ""))

    ap_start_date_ire = _handle_type(ireland_additional_data.get("apStartDate", ""))
    ap_end_date_ire = _handle_type(ireland_additional_data.get("apEndDate", ""))

    ap_start_date_ldn = _handle_type(london_additional_data.get("apStartDate", ""))
    ap_end_date_ldn = _handle_type(london_additional_data.get("apEndDate", ""))

    suspension_date_ire = _handle_type(
        ireland_additional_data.get("suspensionDate", "")
    )
    suspension_date_ldn = _handle_type(london_additional_data.get("suspensionDate", ""))

    statement_created_date_ire = _handle_type(
        ireland_additional_data.get("statementCreatedDate", "")
    )
    statement_created_date_ldn = _handle_type(
        london_additional_data.get("statementCreatedDate", "")
    )

    return {
        "nino": nino,
        "statement_id": statement_id.replace('"', ""),
        "decrypted_take_home_pay": take_home_pay,
        "contract_id_ire": contract_id_ire,
        "contract_id_ldn": contract_id_ldn,
        "ap_start_date_ire": ap_start_date_ire,
        "ap_end_date_ire": ap_end_date_ire,
        "ap_start_date_ldn": ap_start_date_ldn,
        "ap_end_date_ldn": ap_end_date_ldn,
        "suspension_date_ire": suspension_date_ire,
        "suspension_date_ldn": suspension_date_ldn,
        "statement_created_date_ire": statement_created_date_ire,
        "statement_created_date_ldn": statement_created_date_ldn,
    }


def _handle_type(variable: Union[str, bytes]):
    return variable if not isinstance(variable, bytes) else variable.decode()


def dynamodb_record_mismatch_record(ddb_table, data):
    try:
        logger.info(
            f'Attempting to put item into DynamoDb", '
            f'"nino": "{data["nino"]}, "ddb_record_mismatch_table": "{ddb_table.name}"'
        )

        response = ddb_table.put_item(Item=data)

        logger.info(f'Recorded mismatch record into DynamoDB", "response": "{response}')

    except Exception as e:
        logger.error(
            f'Error attempting to put dynamoDB record", '
            f'"table_name": "{ddb_table.name}", "exception": "{e}'
        )
        raise e


def get_matches(ire_data: List[dict], ldn_data: List[dict]):
    matches = []
    non_matches = []

    ire_copy = ire_data.copy()
    ldn_copy = ldn_data.copy()

    for ire_row in ire_data:
        for ldn_row in ldn_data:
            if ire_row["nino"] == ldn_row["nino"] and ire_row.get(
                "statement_id", ""
            ) == ldn_row.get("statement_id", ""):
                matches.append({"ire": ire_row, "ldn": ldn_row})

                ire_copy.remove(ire_row)
                ldn_copy.remove(ldn_row)

    for row in ire_copy:
        non_matches.append({"ire": row, "ldn": {}})

    for row in ldn_copy:
        non_matches.append({"ire": {}, "ldn": row})

    return matches, non_matches


args = None
logger = None


def handler(event, context):
    global args
    args = get_parameters()
    global logger
    logger = setup_logging(args.log_level)

    logger.info(f'Event", "event": "{event}')

    nino = event["nino"]
    transaction_id = event["transaction_id"]
    take_home_pay = event["take_home_pay"]

    logger.info(
        f'Requesting additional data for unmatched record", "nino": "{nino}", '
        f'"transaction_id": "{transaction_id}", "take_home_pay": "{take_home_pay}'
    )

    ireland_sql_password = get_parameter_store_value(
        args.ireland_rds_parameter, args.ireland_parameter_region
    )
    ireland_connection = get_connection(
        args.ireland_rds_hostname,
        args.ireland_rds_username,
        ireland_sql_password,
        args.ireland_database_name,
        args.use_ssl,
        logger,
    )

    ireland_additional_data = get_additional_record_data(nino, ireland_connection)

    london_sql_password = get_parameter_store_value(
        args.london_rds_parameter, args.london_parameter_region
    )
    london_connection = get_connection(
        args.london_rds_hostname,
        args.london_rds_username,
        london_sql_password,
        args.london_database_name,
        args.use_ssl,
        logger,
    )

    london_additional_data = get_additional_record_data(nino, london_connection)

    ire_len = len(ireland_additional_data)
    ldn_len = len(london_additional_data)

    if ire_len != ldn_len:
        logger.warning(
            'Mismatch of length between ireland & london additional data", '
            f'"ireland_length": "{ire_len}", "london_length": "{ldn_len}" '
            f'"ireland_additional_data": "{ireland_additional_data}" '
            f'"london_additional_data": "{london_additional_data} '
        )

    dynamo_table = boto3.resource("dynamodb", args.aws_region).Table(args.ddb_record_mismatch_table)

    matches, non_matches = get_matches(ireland_additional_data, london_additional_data)

    for match in matches:
        logger.info(
            f'Attempting to format into DynamoDb structure", "record": "{match}'
        )
        dynamodb_data = dynamodb_format(nino, take_home_pay, match["ire"], match["ldn"])

        logger.info(
            f'Recording mismatch record into DynamoDB",'
            f'"ddb_record_mismatch_table": "{args.ddb_record_mismatch_table}", '
            f'"nino": "{nino}'
        )
        dynamodb_record_mismatch_record(dynamo_table, dynamodb_data)

    for row in non_matches:
        logger.info(f'Attempting to format into DynamoDb structure", "record": "{row}')
        dynamodb_data = dynamodb_format(nino, take_home_pay, row["ire"], row["ldn"])

        logger.info(
            f'Recording mismatch record into DynamoDB",'
            f'"ddb_record_mismatch_table": "{args.ddb_record_mismatch_table}", '
            f'"nino": "{nino}'
        )
        dynamodb_record_mismatch_record(dynamo_table, dynamodb_data)


if __name__ == "__main__":
    try:
        args = get_parameters()
        logger = setup_logging("INFO")

        boto3.setup_default_session(region_name=args.aws_region)
        logger.info(os.getcwd())
        json_content = json.loads(open("resources/event.json", "r").read())
        handler(json_content, None)
    except Exception as err:
        logger.error(f'Exception occurred for invocation", "error_message": "{err}')
        raise err
