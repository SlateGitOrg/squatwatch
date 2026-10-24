# squatwatch developer entry points. `make check` is the single gate (also run in CI).
UV ?= uv
RUN = $(UV) run --frozen
COV_MIN = 85

.PHONY: help sync check fmt lint type test cov fixtures-check demo eval bench fixtures snapshot incidents clean

help:
	@echo "make check   - format check, lint, type check, fixture check, tests + coverage gate"
	@echo "make demo    - offline end-to-end demo against bundled fixtures"
	@echo "make eval    - labelled evaluation (dev sweep + held-out test) -> eval/RESULTS.md"
	@echo "make bench   - name-check throughput benchmark"
	@echo "make fmt     - apply formatting"

sync:
	$(UV) sync --frozen

check: sync
	$(RUN) ruff format --check src tests scripts
	$(RUN) ruff check src tests scripts
	$(RUN) mypy
	$(RUN) python scripts/build_archives.py --check
	$(RUN) pytest --cov=squatwatch --cov-branch --cov-report=term-missing --cov-fail-under=$(COV_MIN)

fmt:
	$(RUN) ruff format src tests scripts
	$(RUN) ruff check --fix src tests scripts

demo: sync
	@bash scripts/demo.sh

eval: sync
	$(RUN) squatwatch eval --data-dir data/eval -o eval/RESULTS.md
	@cat eval/RESULTS.md

bench: sync
	$(RUN) python scripts/bench.py

fixtures:
	$(RUN) python scripts/build_archives.py

# Network-only maintenance targets (never part of `make check`).
snapshot:
	$(RUN) python scripts/fetch_popular.py

incidents:
	$(RUN) python scripts/build_incidents.py

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov out
