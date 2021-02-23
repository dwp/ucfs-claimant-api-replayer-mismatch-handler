# ucfs-claimant-api-replayer-mismatch-handler

## An AWS lambda which receives requests and a response payload, to replay against the v1 UCFS Claimant API in London to assert responses are equal.

This repo contains Makefile to fit the standard pattern.
This repo is a base to create new non-Terraform repos, adding the githooks submodule, making the repo ready for use.

After cloning this repo, please run:  
`make bootstrap`
