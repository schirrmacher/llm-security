import argparse

from security_army_knife.commands.cve import (
    run_cve_analysis,
    add_subcommand as add_cve_parser,
)
from security_army_knife.commands.sdr import (
    run_sdr_analysis,
    add_subcommand as add_sdr_parser,
)
from security_army_knife.commands.util import setup_logging


def main():

    parser = argparse.ArgumentParser(
        description="Security Army Knife - AI for security day to day tasks"
    )

    subparsers = parser.add_subparsers(dest="command", help="Subcommands")
    add_cve_parser(subparsers)
    add_sdr_parser(subparsers)
    args = parser.parse_args()

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
            infrastructure_code=args.infra,
            state_file_path=args.state,
            # output
            large_language_model=args.large_language_model,
            output_option=args.output,
            output_format=args.output_format,
            output_filename=args.output_filename,
        )
        return result_code
    if args.command == "sdr":
        result_code = run_sdr_analysis(
            architecture_diagram=args.architecture_diagram,
            api_documentation=args.api_documentation,
            large_language_model=args.large_language_model,
            output_format=args.output_format,
            output_filename=args.output_filename,
        )
        return result_code
    else:
        print("Unknown command")
        return 1


if __name__ == "__main__":
    exit(main())
