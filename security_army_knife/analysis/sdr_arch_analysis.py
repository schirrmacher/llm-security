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
        assets: List[str],
    ):
        self.flow = flow
        self.protocol = protocol
        self.authentication = authentication
        self.environmentSrc = environmentSrc
        self.environmentDst = environmentDst
        self.assets = assets


class SoftwareArtifact:
    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category


class SDRArchAnalysis:
    def __init__(
        self,
        assets: List[Asset],
        entrypoints: List[Entrypoint],
        persistence_layers: List[PersistenceLayer],
        software_artifacts: List[SoftwareArtifact],
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
        software_artifacts = [
            SoftwareArtifact(**artifact)
            for artifact in json_data.get("software_artifacts", [])
        ]
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

    def to_dict(self) -> dict:
        return {
            "assets": [asset.__dict__ for asset in self.assets],
            "software_artifacts": [
                artifact.__dict__ for artifact in self.software_artifacts
            ],
            "entrypoints": [
                entrypoint.__dict__ for entrypoint in self.entrypoints
            ],
            "persistence_layers": [
                persistence_layer.__dict__
                for persistence_layer in self.persistence_layers
            ],
            "dataflows": [dataflow.__dict__ for dataflow in self.dataflows],
        }

    def to_json(self) -> dict:
        return self.to_dict()

    def to_yaml(self) -> str:
        return yaml.dump(self.to_dict(), sort_keys=False)

    def to_markdown(self) -> str:
        md = ""
        md += "## Assets\n"
        for asset in self.assets:
            md += f"- **{asset.name}**: {asset.category}\n"

        md += "## Software Artifacts\n"
        for artifact in self.software_artifacts:
            md += f"- **{artifact.name}**: {artifact.category}\n"

        md += "## Entrypoints\n"
        for entrypoint in self.entrypoints:
            md += f"- **{entrypoint.name}**:\n"
            md += f"  - **Protocol**: {entrypoint.protocol}\n"
            md += f"  - **Authentication**: {entrypoint.authentication}\n"
            md += f"  - **Environment**: {entrypoint.environment}\n\n"

        md += "## Persistence Layers\n"
        for pl in self.persistence_layers:
            md += f"- **{pl.name}**: {', '.join(pl.assets)}\n"

        md += "\n## Dataflows\n"
        for df in self.dataflows:
            md += f"- **{df.flow}**:\n"
            md += f"  - **Protocol**: {df.protocol}\n"
            md += f"  - **Authentication**: {df.authentication}\n"
            md += f"  - **Environment Source**: {df.environmentSrc}\n"
            md += f"  - **Environment Destination**: {df.environmentDst}\n"
            md += f"  - **Assets**: {', '.join(df.assets)}\n\n"

        return md
