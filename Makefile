.PHONY: up down logs build lint format-check typecheck test test-integration smoke migrate seed validate reset

up:
	sh scripts/dev.sh up

down:
	sh scripts/dev.sh down

logs:
	sh scripts/dev.sh logs

build:
	sh scripts/dev.sh build

lint:
	sh scripts/dev.sh lint

format-check:
	sh scripts/dev.sh format-check

typecheck:
	sh scripts/dev.sh typecheck

test:
	sh scripts/dev.sh test

test-integration:
	sh scripts/dev.sh test-integration

smoke:
	sh scripts/dev.sh smoke

migrate:
	sh scripts/dev.sh migrate

seed:
	sh scripts/dev.sh seed

validate:
	sh scripts/dev.sh validate

reset:
	sh scripts/dev.sh reset --confirm
