# UCFS Claimant API Replayer Mismatch Handler

## An AWS lambda which receives a payload of mismatch records from the replayer lambda, collects additional data from both databases and records in DynamoDb for reporting purposes.

This repo contains Makefile to fit the standard pattern.
This repo is a base to create new non-Terraform repos, adding the githooks submodule, making the repo ready for use.

After cloning this repo, please run:  
`make bootstrap`
