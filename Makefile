.PHONY: setup format test run

setup:
	@echo "Creating virtual environment..."
	python3 -m venv sak
	@echo "Installing dependencies..."
	. sak/bin/activate;
	sak/bin/pip3 install -e .


format:
	@echo "Formatting code..."
	. sak/bin/activate; \
	sak/bin/python3 -m black --config pyproject.toml tests api security_army_knife --check

test:
	@echo "Running tests..."
	. sak/bin/activate; \
	sak/bin/pytest tests
