from replayer_lambda.config import get_parameter_store_value
import mysql.connector
import os


def get_connection(rds_endpoint, username, password, database_name):
    script_dir = os.path.dirname(__file__)
    rel_path = "rds-ca-2019-root.pem"
    abs_file_path = os.path.join(script_dir, rel_path)

    logger.info(f"Path to the CR cert is '{abs_file_path}'")

    return mysql.connector.connect(
        host=rds_endpoint,
        user=username,
        password=password,
        database=database_name,
        ssl_ca=abs_file_path,
        ssl_verify_cert=True if args.use_ssl.lower() == "true" else False
    )


def get_additional_record_data(nino, transaction_id, connection):
    sql = f"""
    SELECT
      claimant.nino,
      contract.contract_id,
      contract.data->'$.claimSuspension.suspensionDate' AS suspensionDate,
      statement.data->'$.assessmentPeriod.startDate' AS apStartDate,
      statement.data->'$.assessmentPeriod.endDate' AS apEndDate,
      statement.data->>'$.createdDateTime.$date' statementCreatedDate,
      statement.data->>'$.encryptedTakeHomePay' AS encryptedTakeHomePay
    FROM claimant
    LEFT JOIN contract ON claimant.citizen_id = contract.citizen_a
    LEFT JOIN statement ON statement.contract_id = contract.contract_id
    WHERE contract.data->>'$.closedDate' = 'null' AND nino = {nino}"
    UNION SELECT
      claimant.nino,
      contract.contract_id,
      contract.data->'$.claimSuspension.suspensionDate' AS suspensionDate,
      statement.data->'$.assessmentPeriod.startDate' AS apStartDate,
      statement.data->'$.assessmentPeriod.endDate' AS apEndDate,
      statement.data->>'$.createdDateTime.$date' statementCreatedDate,
      statement.data->>'$.encryptedTakeHomePay' AS encryptedTakeHomePay
    FROM claimant
    LEFT JOIN contract ON claimant.citizen_id = contract.citizen_b
    LEFT JOIN statement ON statement.contract_id = contract.contract_id
    WHERE contract.data->>'$.closedDate' = 'null' AND nino = "{nino}"
    ORDER BY apStartDate DESC, statementCreatedDate DESC;
    """
    response = execute_statement(sql, connection)
    # TODO Pack results in a dict as expected by ddb func
    packed_dict = {}
    return packed_dict


def execute_statement(sql, connection):
    cursor = connection.cursor()
    cursor.execute(sql)
    logger.info("Executed: {}".format(sql))
    connection.commit()
