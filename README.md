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

#### Install dependencies

```
make setup
```

#### Execute tests

```
make test
```

#### Format code

```
make format
```

### Manipulate State (`state.json`)

#### Remove categorization

```
make state_remove_categories
```

#### Remove code analysis

```
make state_remove_code_analysis
```
