import unittest
from security_army_knife.analysis.sdr import SDR


class TestSDRFromJson(unittest.TestCase):
    def setUp(self):
        # Sample JSON data for SDRArchAnalysis and SDRThreats
        self.sample_arch_analysis_json = {
            "assets": [
                {"name": "Asset1", "category": "Category1"},
                {"name": "Asset2", "category": "Category2"},
            ],
            "entrypoints": [
                {
                    "name": "Entrypoint1",
                    "protocol": "HTTPS",
                    "authentication": "OAuth",
                    "environment": "Production",
                },
                {
                    "name": "Entrypoint2",
                    "protocol": "HTTP",
                    "authentication": "None",
                    "environment": "Development",
                },
            ],
            "persistence_layers": [
                {"name": "Layer1", "assets": ["Asset1", "Asset2"]},
            ],
            "software_artifacts": [
                {"name": "Artifact1", "category": "CategoryA"},
                {"name": "Artifact2", "category": "CategoryB"},
            ],
            "dataflows": [
                {
                    "flow": "Flow1",
                    "protocol": "TCP",
                    "authentication": "Token",
                    "environmentSrc": "Env1",
                    "environmentDst": "Env2",
                    "protection": "Encryption",
                    "assets": ["Asset1"],
                },
            ],
        }
        self.sample_threats_json = {
            "threats": [
                {
                    "threat": "Threat1",
                    "components": ["Component1", "Component2"],
                    "condition": "Condition1",
                    "score": 5,
                    "mitigations": ["Mitigation1", "Mitigation2"],
                },
                {
                    "threat": "Threat2",
                    "components": ["Component3"],
                    "condition": "Condition2",
                    "score": 3,
                    "mitigations": ["Mitigation3"],
                },
            ]
        }

    def test_from_json_arch_analysis_only(self):
        json_data = {
            "arch_analysis": self.sample_arch_analysis_json,
            "threats": None,
        }
        sdr = SDR.from_json(json_data)
        self.assertIsNotNone(sdr.arch_analysis)
        self.assertIsNone(sdr.threats)
        self.assertEqual(len(sdr.arch_analysis.assets), 2)
        self.assertEqual(len(sdr.arch_analysis.entrypoints), 2)
        self.assertEqual(len(sdr.arch_analysis.persistence_layers), 1)
        self.assertEqual(len(sdr.arch_analysis.software_artifacts), 2)
        self.assertEqual(len(sdr.arch_analysis.dataflows), 1)

    def test_from_json_threats_only(self):
        json_data = {"arch_analysis": None, "threats": self.sample_threats_json}
        sdr = SDR.from_json(json_data)
        self.assertIsNone(sdr.arch_analysis)
        self.assertIsNotNone(sdr.threats)
        self.assertEqual(len(sdr.threats.threats), 2)

    def test_from_json_both(self):
        json_data = {
            "arch_analysis": self.sample_arch_analysis_json,
            "threats": self.sample_threats_json,
        }
        sdr = SDR.from_json(json_data)
        self.assertIsNotNone(sdr.arch_analysis)
        self.assertIsNotNone(sdr.threats)
        self.assertEqual(len(sdr.arch_analysis.assets), 2)
        self.assertEqual(len(sdr.arch_analysis.entrypoints), 2)
        self.assertEqual(len(sdr.arch_analysis.persistence_layers), 1)
        self.assertEqual(len(sdr.arch_analysis.software_artifacts), 2)
        self.assertEqual(len(sdr.arch_analysis.dataflows), 1)
        self.assertEqual(len(sdr.threats.threats), 2)

    def test_from_json_empty(self):
        json_data = {}
        sdr = SDR.from_json(json_data)
        self.assertIsNone(sdr.arch_analysis)
        self.assertIsNone(sdr.threats)


if __name__ == "__main__":
    unittest.main()
