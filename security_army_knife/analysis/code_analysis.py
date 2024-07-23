class CodeAnalysis:
    def __init__(
        self,
        queries: list[str] = [],
        affected_files: list[str] = [],
    ):
        self.queries = queries
        self.affected_files = affected_files

    @classmethod
    def from_json(cls, json_dict: dict):
        return cls(
            queries=json_dict.get("queries", []),
            affected_files=json_dict.get("affected_files", []),
        )

    def to_json(self):
        return {
            "queries": self.queries,
            "affected_files": self.affected_files,
        }

    def __str__(self):
        queries_str = ", ".join(self.queries)
        files_str = ", ".join(self.affected_files)
        return f"Code Analysis:\n  Queries: {queries_str}\n  Affected Files: {files_str}"
