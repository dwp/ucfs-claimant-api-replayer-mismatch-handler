# DO NOT USE THIS REPO - MIGRATED TO GITLAB

# UCFS Claimant API Replayer Mismatch Handler

## An AWS lambda which receives a payload of mismatch records from the replayer lambda, collects additional data from both databases and records in DynamoDb for reporting purposes.

This repo contains Makefile to fit the standard pattern.
This repo is a base to create new non-Terraform repos, adding the githooks submodule, making the repo ready for use.

After cloning this repo, please run:  
`make bootstrap`

# Environment Variables
|Variable name|Example|Description|
|---|:---:|:---|
|AWS_REGION|eu-west-1|The region where the Lambda is located|
|ENVIRONMENT|DEV OR PROD|The environment the Lambda is located in (used in logging)|
|APPLICATION|ucfs-claimant-api-replayer-mismatch-handler |The name of the Lambda|
|LOG_LEVEL|INFO or DEBUG|The logging level of the Lambda|
|USE_SSL|true or false|Whether or not SSL should be used when connecting to RDS|
|IRELAND_RDS_HOSTNAME|AWS RDS endpoint|The endpoint to reach the Ireland RDS|
|IRELAND_RDS_USERNAME|db-user|The username to be used when connecting to the Ireland RDS|
|IRELAND_RDS_PARAMETER|SSM parameter name|The SSM key for retrieving the Ireland RDS password|
|IRELAND_DATABASE_NAME|db_schema|The name of the Ireland database to be used|
|LONDON_RDS_HOSTNAME|AWS RDS endpoint|The endpoint to reach the London RDS|
|LONDON_RDS_USERNAME|db-user|The username to be used when connecting to the London RDS|
|LONDON_RDS_PARAMETER|SSM parameter name|The SSM key for retrieving the Ireland RDS password|
|LONDON_DATABASE_NAME|db_schema|The name of the London database to be used|
|DDB_RECORD_MISMATCH_TABLE|table-name|The name of the DDB table used to record mismatched records|
|IRELAND_PARAMETER_REGION|eu-west-1|The region in which the Ireland RDS password will be found in SSM|
|LONDON_PARAMETER_REGION|eu-west-2|The region in which the London RDS password will be found in SSM|

# How to run
Create a MYSQL container locally (e.g via docker)  
Setup MYSQL databases & tables, refer to [these SQL scripts](https://github.com/dwp/ucfs-claimant-api-load-data/tree/master/src)  
Set IRELAND_RDS_* & LONDON_RDS_* environment vars appropriately  
Ensure there are mismatching records across "Ireland" and "London" LOCAL Claimant API RDS databases for a matching NINO  
Ensure you have correctly set all of the environment variables in the above table  
Run `make run-local`, this will use the example event `resources/event.json`

# Data analysis

Fetch sample data for a given time period via AWS CLI. Replacing TABLE-NAME and PROFILE with the respective values.
```
aws dynamodb scan --table-name TABLE-NAME --filter-expression 'contains(recorded_datetime,:date)' --expression-attribute-values '{":date":{"S":"2021-03-06T"}}' --profile PROFILE --region eu-west-1 --output json > claimant_api.json
```

Run the `dynamodb_to_csv` script to convert the DynamoDb output to CSV for the mismatch dynamodb table structure.
Send this CSV to UC via secure means.
