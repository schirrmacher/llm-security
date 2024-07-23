# Security Army Knife

This repository contains security utilities. The features will be announced soon.

![alt text](logo.png)

## Run

First run `make setup`, then:

```
sak/bin/sak -cve examples/cve-advisories.json \
    -dep examples/dependencies.csv \
    -arc examples/architecture.d2 \
    -api examples/swagger-open-api.json \
    -src examples
```

## Developing

Install dependencies:

```
make setup
```

Execute tests:

```
make test
```

Format code:

```
make format
```

### Manipulate `state.json`

```
# Remove categorization
jq 'map(del(.category))' state.json > state.json

# Remove code analysis
jq 'map(del(.code_analysis))' state.json > state.json
```
