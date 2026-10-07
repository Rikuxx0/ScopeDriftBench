PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
SCENARIO ?= S1
CONDITION ?= A
SEED ?= 42
RUNS ?= 5
DIFFICULTY ?= equal
MODEL ?= gpt-5.6-luna
VARIANT ?= medium

.PHONY: build up down auth-login auth-status auth-logout healthcheck agent-smoke run execute dynamic-run reset evaluate reparse batch report test

build:
	./scripts/build.sh

up:
	./scripts/up.sh

auth-login:
	docker compose exec pentestcode pentestcode auth login --provider openai --method "ChatGPT Pro/Plus (headless)"

auth-status:
	docker compose exec -T pentestcode pentestcode auth list

auth-logout:
	docker compose exec pentestcode pentestcode auth logout openai

down:
	./scripts/down.sh

healthcheck:
	./scripts/healthcheck.sh

agent-smoke:
	docker compose exec -T pentestcode pentestcode --version
	docker compose exec -T pentestcode nmap -sT -n -Pn -p 8000 10.10.1.10 10.10.2.10

run:
	$(PYTHON) -m runner.run_experiment prepare --scenario $(SCENARIO) --condition $(CONDITION) --seed $(SEED) --difficulty $(DIFFICULTY) --agent pentestcode

execute:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" && exit 2)
	$(PYTHON) -m runner.run_experiment execute --run-id $(RUN_ID) --model $(MODEL) --variant $(VARIANT)

dynamic-run:
	$(PYTHON) -m runner.run_experiment dynamic --scenario $(SCENARIO) --condition $(CONDITION) --seed $(SEED) --difficulty $(DIFFICULTY) --model $(MODEL) --variant $(VARIANT)

reset:
	./scripts/reset.sh

evaluate:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" && exit 2)
	./scripts/evaluate.sh $(RUN_ID)

reparse:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" && exit 2)
	$(PYTHON) -m runner.run_experiment reparse --run-id $(RUN_ID)

batch:
	$(PYTHON) -m runner.batch --scenarios $(SCENARIO) --conditions A,B,C --seeds $$(seq -s, 1 $(RUNS)) --difficulty $(DIFFICULTY)

report:
	$(PYTHON) -m evaluator.report

test:
	$(PYTHON) -m pytest -q
