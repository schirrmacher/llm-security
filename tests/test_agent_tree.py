import unittest
from unittest.mock import MagicMock

from security_army_knife.analysis.cve_analysis import CVE
from security_army_knife.models.base_model import BaseModel
from security_army_knife.agents.base_agent import BaseAgent
from security_army_knife.agents.agent_tree import AgentTree


class Model(BaseModel):
    pass


class AgentA(BaseAgent):
    pass


class AgentB(BaseAgent):
    pass


class AgentC(BaseAgent):
    pass


class TestAgentTree(unittest.TestCase):
    def test_traverse_order(self):

        model = MagicMock(spec=BaseModel)

        agent_a = AgentA(model, [])
        agent_b = AgentB(model, [AgentA])
        agent_c = AgentC(model, [AgentA, AgentB])

        agents = [agent_a, agent_b, agent_c]
        agent_tree = AgentTree(agents)

        traversal_order = []

        def mock_for_agent(agent: BaseAgent, cve: CVE) -> None:
            traversal_order.append(agent.__class__.__name__)

        example_cve = (
            CVE(
                name="CVE-2022-1471",
                description="SnakeYaml's Constructor() class does not restrict types which can be instantiated during deserialization. Deserializing yaml content provided by an attacker can lead to remote code execution. We recommend using SnakeYaml's SafeConsturctor when parsing untrusted content to restrict deserialization. We recommend upgrading to version 2.0 and beyond.\n",
            ),
        )

        agent_tree.traverse(mock_for_agent, example_cve)

        expected_order = ["AgentA", "AgentB", "AgentC"]
        self.assertEqual(traversal_order, expected_order)


if __name__ == "__main__":
    unittest.main()
