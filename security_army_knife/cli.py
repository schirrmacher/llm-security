from security_army_knife.commands.cve import (
    run_cve_analysis,
    parse_arguments as cve_arguments,
)
from security_army_knife.commands.util import setup_logging


def main():
    args = cve_arguments()
    setup_logging(args.log_level)
    if args.command == "cve":
        result_code = run_cve_analysis(
            # input
            cve_file_path=args.cve_list,
            trivy_file_path=args.trivy_json,
            architecture_diagram=args.architecture_diagram,
            dependency_list=args.dependency_list,
            api_documentation=args.api_documentation,
            source_code=args.source_code,
            state_file_path=args.state,
            # output
            large_language_model=args.large_language_model,
            output_option=args.output,
            output_format=args.output_format,
        )
        return result_code
    else:
        print("Unknown command")
        return 1


if __name__ == "__main__":
    exit(main())
