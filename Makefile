# Trida AI Blueprint — AML Alert Investigation & Case File Agent
#
# Primary workflow is uv (https://docs.astral.sh/uv/):
#   make install     uv sync --extra dev
#   make demo        one seeded alert end to end, offline (no keys)
#   make test        pytest
#   make evals       R1 eval gate, offline (in-memory stack)
#   make serve       the API on http://localhost:8000
#
# No uv? python3 -m venv .venv && source .venv/bin/activate, then:
#   make install-pip

.PHONY: install install-pip demo test evals serve

install:
	uv sync --extra dev

install-pip:
	# The frozen, hash-verified set first, then the package itself with
	# --no-deps: pip refuses an editable install under a hashed
	# constraints file, so the two steps never mix.
	pip install -r constraints.txt
	pip install --no-deps -e .
	pip install "pytest==9.1.1" "httpx==0.28.1"

demo:
	uv run aml-agent-demo

test:
	uv run pytest -q

evals:
	uv run python evals/run_evals.py

serve:
	uv run uvicorn aml_investigations.api:app --port 8000
