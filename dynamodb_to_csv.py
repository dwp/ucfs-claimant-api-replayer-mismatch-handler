import json
import csv

field_names = [
    "nino",
    "statement_id",
    "recorded_datetime",
    "decrypted_take_home_pay",
    "contract_id_ire",
    "contract_id_ldn",
    "ap_start_date_ire",
    "ap_end_date_ire",
    "ap_start_date_ldn",
    "ap_end_date_ldn",
    "suspension_date_ire",
    "suspension_date_ldn",
    "statement_created_date_ire",
    "statement_created_date_ldn",
]

with open("claimant_mismatch.csv", "w", newline="") as csvfile:
    csvwriter = csv.DictWriter(csvfile, fieldnames=field_names)

    csvwriter.writeheader()

    def json_to_csv(json):
        for item in json["Items"]:
            row_items = {}

            for key, value in item.items():
                subkey, subvalue = list(value.items())[0]
                if subkey == "NULL":
                    row_items[key] = "null"
                else:
                    row_items[key] = subvalue

            csvwriter.writerow(row_items)

    def load_json():
        file = open("claimant_mismatch.json", "r")
        return json.loads(file.read())

    json_file = load_json()
    json_to_csv(json_file)
