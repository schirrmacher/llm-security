import os
import logging
import argparse

from security_army_knife.gemini_model import GeminiModel
from security_army_knife.mistral_model import MistralModel
from security_army_knife.base_model import BaseModel

ASCII_ART = """
░█▀▀░█▀▀░█▀▀░█░█░█▀▄░▀█▀░▀█▀░█░█░░░█▀█░█▀▄░█▄█░█░█░░░█░█░█▀█░▀█▀░█▀▀░█▀▀
░▀▀█░█▀▀░█░░░█░█░█▀▄░░█░░░█░░░█░░░░█▀█░█▀▄░█░█░░█░░░░█▀▄░█░█░░█░░█▀▀░█▀▀
░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░░▀░░░▀░░░░▀░▀░▀░▀░▀░▀░░▀░░░░▀░▀░▀░▀░▀▀▀░▀░░░▀▀▀
"""


def setup_logging(log_level):
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
    )
    logger = logging.getLogger("SecurityArmyKnife")
    logger.info(ASCII_ART)


def get_model(large_language_model: str) -> BaseModel:
    if large_language_model == "mistral":
        return MistralModel()
    elif large_language_model == "gemini":
        return GeminiModel()
    else:
        raise ValueError(f"{large_language_model} not supported.")


def is_valid_directory(path):
    """Check if the given path is a valid directory."""
    if not os.path.isdir(path):
        raise argparse.ArgumentTypeError(f"'{path}' is not a valid directory.")
    return path


def is_valid_file(path):
    """Check if the given path is a valid directory."""
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"'{path}' is not a valid file.")
    return path
