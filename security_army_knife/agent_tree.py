import networkx as nx
from typing import Callable

from security_army_knife.analysis.cve import CVE
from security_army_knife.agents.base_agent import BaseAgent


def build_dependency_graph(agents: list[BaseAgent]) -> nx.DiGraph:
    G = nx.DiGraph()
    for agent in agents:
        agent_name = agent.__class__.__name__
        G.add_node(agent_name)
        for dependency in agent.dependencies:
            G.add_edge(dependency, agent_name)

    return G


def resolve_dependencies(agents: list[BaseAgent]) -> list[str]:
    G = build_dependency_graph(agents)
    try:
        resolved_order = list(nx.topological_sort(G))
        return resolved_order
    except nx.NetworkXUnfeasible as e:
        raise Exception(f"Agent graph has a cycle: {e}")


class AgentTree:

    agents: list[BaseAgent]

    def __init__(self, agents: list[BaseAgent]):
        self.agents = agents

    def traverse(
        self,
        for_agent: Callable[[BaseAgent, list[CVE]], list[CVE]],
        cve_list: list[CVE],
    ) -> None:

        order = resolve_dependencies(self.agents)
        agent_map = {agent.__class__.__name__: agent for agent in self.agents}

        for agent_name in order:
            agent = agent_map[agent_name]
            cve_list = for_agent(agent, cve_list)
