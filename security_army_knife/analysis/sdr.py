import yaml
from typing import List


class Asset:
    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category


class Entrypoint:
    def __init__(
        self, name: str, protocol: str, authentication: str, environment: str
    ):
        self.name = name
        self.protocol = protocol
        self.authentication = authentication
        self.environment = environment


class PersistenceLayer:
    def __init__(self, name: str, assets: List[str]):
        self.name = name
        self.assets = assets


class Dataflow:
    def __init__(
        self,
        flow: str,
        protocol: str,
        authentication: str,
        environmentSrc: str,
        environmentDst: str,
        protection: str,
        assets: List[str],
    ):
        self.flow = flow
        self.protocol = protocol
        self.authentication = authentication
        self.environmentSrc = environmentSrc
        self.environmentDst = environmentDst
        self.protection = protection
        self.assets = assets


class SDR:
    def __init__(
        self,
        assets: List[Asset],
        entrypoints: List[Entrypoint],
        persistence_layers: List[PersistenceLayer],
        software_artifacts: List[dict],
        dataflows: List[Dataflow],
    ):
        self.assets = assets
        self.entrypoints = entrypoints
        self.persistence_layers = persistence_layers
        self.software_artifacts = software_artifacts
        self.dataflows = dataflows

    @classmethod
    def from_json(cls, json_data: dict):
        assets = [Asset(**asset) for asset in json_data.get("assets", [])]
        entrypoints = [
            Entrypoint(**entrypoint)
            for entrypoint in json_data.get("entrypoints", [])
        ]
        persistence_layers = [
            PersistenceLayer(**persistence_layer)
            for persistence_layer in json_data.get("persistence_layers", [])
        ]
        software_artifacts = json_data.get("software_artifacts", [])
        dataflows = [
            Dataflow(**dataflow) for dataflow in json_data.get("dataflows", [])
        ]
        return cls(
            assets,
            entrypoints,
            persistence_layers,
            software_artifacts,
            dataflows,
        )

    def to_json(self):
        return {
            "assets": [asset.__dict__ for asset in self.assets],
            "entrypoints": [
                entrypoint.__dict__ for entrypoint in self.entrypoints
            ],
            "persistence_layers": [
                persistence_layer.__dict__
                for persistence_layer in self.persistence_layers
            ],
            "software_artifacts": self.software_artifacts,
            "dataflows": [dataflow.__dict__ for dataflow in self.dataflows],
        }

    def to_yaml(self):
        return yaml.dump(self.to_json(), sort_keys=False)

    def __str__(self):
        return self.to_yaml()
