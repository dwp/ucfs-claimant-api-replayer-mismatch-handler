import mysql.connector
import os

from replayer_mismatch.crypto import decrypted_data_key, decrypted_take_home_pay


def get_connection(
    rds_endpoint: str,
    username: str,
    password: str,
    database_name: str,
    use_ssl: str,
    _logger,
):
    global logger
    logger = _logger

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
        ssl_verify_cert=True if use_ssl.lower() == "true" else False,
    )


def get_additional_record_data(nino, connection, kms_client):
    query = f"""
    SELECT
      claimant.nino,
      contract.contract_id,
      contract.data->'$.claimSuspension.suspensionDate' AS suspensionDate,
      statement.data->'$.assessmentPeriod.startDate' AS apStartDate,
      statement.data->'$.assessmentPeriod.endDate' AS apEndDate,
      statement.data->>'$.createdDateTime.$date' statementCreatedDate,
      statement.data->'$._id.statementId' AS statementId,
      statement.data->>'$.encryptedTakeHomePay.takeHomePay' as encrypted_take_home_pay,
      statement.data->>'$.encryptedTakeHomePay.cipherTextBlob' as encrypted_key,
      statement.data->>'$.encryptedTakeHomePay.keyId' as encrypting_key_id
    FROM claimant
    LEFT JOIN contract ON claimant.citizen_id = contract.citizen_a
    LEFT JOIN statement ON statement.contract_id = contract.contract_id
    WHERE contract.data->>'$.closedDate' = 'null' AND nino = '{nino}'
    UNION SELECT
      claimant.nino,
      contract.contract_id,
      contract.data->'$.claimSuspension.suspensionDate' AS suspensionDate,
      statement.data->'$.assessmentPeriod.startDate' AS apStartDate,
      statement.data->'$.assessmentPeriod.endDate' AS apEndDate,
      statement.data->>'$.createdDateTime.$date' statementCreatedDate,
      statement.data->'$._id.statementId' AS statementId,
      statement.data->>'$.encryptedTakeHomePay.takeHomePay' as encrypted_take_home_pay,
      statement.data->>'$.encryptedTakeHomePay.cipherTextBlob' as encrypted_key,
      statement.data->>'$.encryptedTakeHomePay.keyId' as encrypting_key_id
    FROM claimant
    LEFT JOIN contract ON claimant.citizen_id = contract.citizen_b
    LEFT JOIN statement ON statement.contract_id = contract.contract_id
    WHERE contract.data->>'$.closedDate' = 'null' AND nino = '{nino}'
    ORDER BY apStartDate DESC, statementCreatedDate DESC;
    """

    cursor = connection.cursor(dictionary=True)
    cursor.execute(query)
    logger.info("Executed: {}".format(query))
    response = cursor.fetchall()
    cursor.close()

    for result in response:
        if result["encrypted_take_home_pay"]:
            decrypted_key = decrypted_data_key(kms_client, result["encrypted_key"])
            encrypted_take_home_pay = result["encrypted_take_home_pay"]
            take_home_pay = decrypted_take_home_pay(
                decrypted_key, encrypted_take_home_pay
            )
            result["take_home_pay"] = take_home_pay
        else:
            result["take_home_pay"] = ""

    return response
