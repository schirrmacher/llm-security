class CVECategory:
    os = "os"
    distro = "distro"
    app = "app"
    unknown = "unknown"


class CodeAnalysis:
    def __init__(self, queries: list[str] = [], affected_files: list[str] = []):
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


class CVE:
    def __init__(
        self,
        name: str,
        description: str,
        category: str = CVECategory.unknown,
        code_analysis: CodeAnalysis = CodeAnalysis(),
    ):
        self.name = name
        self.description = description
        self.category = category
        self.code_analysis = code_analysis

    @classmethod
    def from_json(cls, json_dict: dict):
        return cls(
            name=json_dict.get("name"),
            description=json_dict.get("description"),
            category=json_dict.get("category", CVECategory.unknown),
            code_analysis=CodeAnalysis.from_json(
                json_dict.get("code_analysis", {})
            ),
        )

    @classmethod
    def from_json_list(cls, json_list: list):
        return [cls.from_json(item) for item in json_list]

    def to_json(self):
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "code_analysis": self.code_analysis.to_json(),
        }

    def __str__(self):
        return (
            f"CVE Name: {self.name}\n"
            f"Description: {self.description}\n"
            f"Category: {self.category}\n"
            f"{self.code_analysis}"
        )
