# Thin proxy: delegates all targets to Taskfile.yml via go-task.
# Install task: go install github.com/go-task/task/v3/cmd/task@latest

TASK := $(shell command -v task 2>/dev/null)

ifndef TASK
  $(info )
  $(info go-task not found. Installing...)
  $(info )
  TASK_INSTALL := $(shell go install github.com/go-task/task/v3/cmd/task@latest 2>&1)
  TASK := $(shell command -v task 2>/dev/null)
  ifndef TASK
    $(error Failed to install go-task. Run manually: go install github.com/go-task/task/v3/cmd/task@latest)
  endif
endif

# Race modifier: `make test race` or `make fulltest race`
ifneq (,$(filter race,$(MAKECMDGOALS)))
  RACE_VAR := RACE=true
endif

.PHONY: all build clean help race install update-bundles update-bundles-diff \
        test unit-test extended-unit-test cli-test stress-test \
        remote-docker-test fulltest localtest \
        testinfra-up testinfra-down

build:
	$(TASK) build

all:
	$(TASK) all

localtest:
	$(TASK) localtest

install:
	$(TASK) install

clean:
	$(TASK) clean

update-bundles:
	$(TASK) update-bundles

update-bundles-diff:
	$(TASK) update-bundles-diff

test:
	$(TASK) test $(RACE_VAR)

unit-test:
	$(TASK) unit-test $(RACE_VAR)

cli-test:
	$(TASK) cli-test

extended-unit-test:
	$(TASK) extended-unit-test $(RACE_VAR)

stress-test:
	$(TASK) stress-test

remote-docker-test:
	$(TASK) remote-docker-test $(RACE_VAR)

testinfra-up:
	$(TASK) testinfra-up

testinfra-down:
	$(TASK) testinfra-down

fulltest:
	$(TASK) fulltest $(RACE_VAR)

race:
	@: # modifier target, consumed by RACE_VAR above

help:
	$(TASK) --list
