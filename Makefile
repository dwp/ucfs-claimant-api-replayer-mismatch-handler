SHELL:=bash

default: help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: bootstrap
bootstrap: ## Bootstrap local environment for first use
	@make git-hooks

.PHONY: git-hooks
git-hooks: ## Set up hooks in .githooks
	@git submodule update --init .githooks ; \
	git config core.hooksPath .githooks \

unittest:
	tox

run-local:
	@{ \
  		export PYTHONPATH=$(shell pwd)/src; \
		python src/replayer_mismatch/handler.py; \
	}

artefact:
	rm -rf artifacts ucfs-claimant-api-replayer-mismatch-handler.zip
	mkdir -p artifacts/replayer_mismatch
	pip install -r requirements.txt -t artifacts
	cp src/replayer_mismatch/*.py artifacts/replayer_mismatch
	cp rds-ca-2019-root.pem artifacts/replayer_mismatch
	@{ \
		cd ./artifacts; \
		zip -qq -r ../ucfs-claimant-api-replayer-mismatch-handler.zip *; \
	}
