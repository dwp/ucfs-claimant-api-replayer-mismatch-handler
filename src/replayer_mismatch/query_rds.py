import mysql.connector
import os

logger = None


def get_connection(
    rds_endpoint: str, username: str, password: str, database_name: str, use_ssl: str
):
    global logger

    script_dir = os.path.dirname(__file__)
    rel_path = "rds-ca-2019-root.pem"
    abs_file_path = os.path.join(script_dir, rel_path)

    if logger is None:
        from handler import logger as __logger

        logger = __logger

    logger.info(f"Path to the CR cert is '{abs_file_path}'")

    return mysql.connector.connect(
        host=rds_endpoint,
        user=username,
        password=password,
        database=database_name,
        ssl_ca=abs_file_path,
        ssl_verify_cert=True if use_ssl.lower() == "true" else False,
    )


def get_additional_record_data(nino, connection):
    query = f"""
    SELECT
      claimant.nino,
      contract.contract_id,
      contract.data->'$.claimSuspension.suspensionDate' AS suspensionDate,
      statement.data->'$.assessmentPeriod.startDate' AS apStartDate,
      statement.data->'$.assessmentPeriod.endDate' AS apEndDate,
      statement.data->>'$.createdDateTime.$date' statementCreatedDate,
      statement.data->'$._id.statementId' AS statementId
    FROM claimant
    LEFT JOIN contract ON claimant.citizen_id = contract.citizen_a
    LEFT JOIN statement ON statement.contract_id = contract.contract_id
    WHERE contract.data->>'$.closedDate' = 'null' AND nino = "{nino}"
    UNION SELECT
      claimant.nino,
      contract.contract_id,
      contract.data->'$.claimSuspension.suspensionDate' AS suspensionDate,
      statement.data->'$.assessmentPeriod.startDate' AS apStartDate,
      statement.data->'$.assessmentPeriod.endDate' AS apEndDate,
      statement.data->>'$.createdDateTime.$date' statementCreatedDate,
      statement.data->'$._id.statementId' AS statementId
    FROM claimant
    LEFT JOIN contract ON claimant.citizen_id = contract.citizen_b
    LEFT JOIN statement ON statement.contract_id = contract.contract_id
    WHERE contract.data->>'$.closedDate' = 'null' AND nino = "{nino}"
    ORDER BY apStartDate DESC, statementCreatedDate DESC;
    """

    cursor = connection.cursor(dictionary=True)
    cursor.execute(query)
    logger.info("Executed: {}".format(query))

    response = cursor.fetchall()

    cursor.close()

    return response
