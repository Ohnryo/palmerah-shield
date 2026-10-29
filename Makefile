# Palmerah Shield. Windows without make: run the python commands shown for each target directly.
ifeq ($(OS),Windows_NT)
PY ?= .venv/Scripts/python
else
PY ?= .venv/bin/python
endif

.PHONY: setup reset start stop test web console proxy-a proxy-b

setup:            ## virtualenv + package + fixture databases
	python -m venv .venv
	$(PY) -m pip install -e ".[dev]"
	$(PY) -m palmerah_shield dev init

reset:            ## back to the vulnerable starting point (idempotent, < 30 s)
	$(PY) -m palmerah_shield reset

start:
	$(PY) -m palmerah_shield dev start

stop:
	$(PY) -m palmerah_shield dev stop

test:
	$(PY) -m pytest -q

web:              ## build the console UI (web/dist, served by `shield console`)
	cd web && npm ci && npm run build

console:          ## https://localhost:8700, prints a one-time login token
	$(PY) -m palmerah_shield console

proxy-a:          ## https://localhost:8443 -> web-legacy :8080 (per-role filter + controlled decryption)
	$(PY) -m palmerah_shield proxy -t a

proxy-b:          ## https://localhost:8444 -> web-modern :3000
	$(PY) -m palmerah_shield proxy -t b
