PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
SCENARIO ?= S1
CONDITION ?= A
SEED ?= 42
RUNS ?= 5
DIFFICULTY ?= equal
MODEL ?= gpt-5.6-luna
VARIANT ?= medium
LIVE_VIEW ?= pretty
AGENT ?= pentestcode
NETWORK_MODE ?= seeded
AUTHORIZATION_PROFILE ?= ambiguous

.PHONY: build up down auth-login auth-status auth-logout healthcheck agent-smoke run execute dynamic-run reset evaluate reparse batch report test

build:
	./scripts/build.sh

up:
	./scripts/up.sh --network-mode $(NETWORK_MODE) --seed $(SEED)

auth-login:
ifeq ($(AGENT),codex)
	./scripts/compose.sh exec codex codex login --device-auth
else
	./scripts/compose.sh exec pentestcode pentestcode auth login --provider openai --method "ChatGPT Pro/Plus (headless)"
endif

auth-status:
ifeq ($(AGENT),codex)
	./scripts/compose.sh exec -T codex codex login status
else
	./scripts/compose.sh exec -T pentestcode pentestcode auth list
endif

auth-logout:
ifeq ($(AGENT),codex)
	./scripts/compose.sh exec codex codex logout
else
	./scripts/compose.sh exec pentestcode pentestcode auth logout openai
endif

down:
	./scripts/down.sh

healthcheck:
	./scripts/healthcheck.sh

agent-smoke:
	./scripts/compose.sh exec -T pentestcode pentestcode --version
	./scripts/compose.sh exec -T codex codex --version
	./scripts/compose.sh exec -T pentestcode nmap -sT -n -Pn -p 8000 target-a target-b
	./scripts/compose.sh exec -T codex nmap -sT -n -Pn -p 8000 target-a target-b

run:
	$(PYTHON) -m runner.run_experiment prepare --scenario $(SCENARIO) --condition $(CONDITION) --seed $(SEED) --network-mode $(NETWORK_MODE) --authorization-profile $(AUTHORIZATION_PROFILE) --difficulty $(DIFFICULTY) --agent $(AGENT) --variant $(VARIANT) --live-view $(LIVE_VIEW)

execute:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" && exit 2)
	$(PYTHON) -m runner.run_experiment execute --run-id $(RUN_ID) --model $(MODEL) --variant $(VARIANT) --live-view $(LIVE_VIEW)

dynamic-run:
	$(PYTHON) -m runner.run_experiment dynamic --scenario $(SCENARIO) --condition $(CONDITION) --seed $(SEED) --network-mode $(NETWORK_MODE) --authorization-profile $(AUTHORIZATION_PROFILE) --difficulty $(DIFFICULTY) --agent $(AGENT) --model $(MODEL) --variant $(VARIANT) --live-view $(LIVE_VIEW)

reset:
	./scripts/reset.sh

evaluate:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" && exit 2)
	./scripts/evaluate.sh $(RUN_ID)

reparse:
	@test -n "$(RUN_ID)" || (echo "RUN_ID is required" && exit 2)
	$(PYTHON) -m runner.run_experiment reparse --run-id $(RUN_ID)

batch:
	$(PYTHON) -m runner.batch --scenarios $(SCENARIO) --conditions A,B,C --seeds $$(seq -s, 1 $(RUNS)) --network-mode $(NETWORK_MODE) --authorization-profiles $(AUTHORIZATION_PROFILE) --difficulty $(DIFFICULTY) --agent $(AGENT) --variant $(VARIANT) --live-view $(LIVE_VIEW)

report:
	$(PYTHON) -m evaluator.report

test:
	$(PYTHON) -m pytest -q
