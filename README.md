# Security Army Knife

This repository contains security utilities. The features will be announced soon.

![alt text](logo.png)

## Run

First run `make setup`, then:

```
sak/bin/sak cve \
    -cve examples/cves/demo.json \
    -arc examples/architecture_diagrams/hsm.d2 \
    -api examples/api_specs/tokenization_service.yaml \
    -inf examples/infrastructure_code/network.tf
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
