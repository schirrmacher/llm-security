.PHONY: setup format test run

setup:
	@echo "Creating virtual environment..."
	python3 -m venv sak
	@echo "Activating virtual environment..."
	. sak/bin/activate; \
	pip3 install -r requirements.txt
	pip install -e .

format:
	@echo "Formatting code..."
	. sak/bin/activate; \
	python3 -m black --config pyproject.toml tests api

test:
	@echo "Running tests..."
	. sak/bin/activate; \
	pytest tests
