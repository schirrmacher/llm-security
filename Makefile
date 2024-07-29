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

state_remove_categories:
	@echo "Manipulating state..."
	jq 'map(del(.category))' state.json > temp_state.json && mv temp_state.json state.json
	
state_remove_code_analysis:
	@echo "Manipulating state..."
	jq 'map(del(.code_analysis))' state.json > temp_state.json && mv temp_state.json state.json

state_remove_api_spec_analysis:
	@echo "Manipulating state..."
	jq 'map(del(.api_spec_analysis))' state.json > temp_state.json && mv temp_state.json state.json

state_remove_architecture_analysis:
	@echo "Manipulating state..."
	jq 'map(del(.architecture_analysis))' state.json > temp_state.json && mv temp_state.json state.json
