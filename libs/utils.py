#!/usr/bin/env python3
import sys
import argparse
import logging

LOG = logging.getLogger('devnet')

def args_manager():
    """
    Parse command-line arguments provide by user
    """

    # All available command line arguments
    parser = argparse.ArgumentParser(prog="DEMO", description="Demo Runner for DEVNET-1369")

    parser.add_argument("-d", "--demo", action="store", required=True, help="Specify the Demo number")

    # Parse arguments (validate user input)
    return parser.parse_args()


def log_manager(debug=None, log_filename=None, logger_name=None):
    """
    Configure logging on console and optionally in a log file
    :param logger_name:
    :param debug: Debug level
    :param log_filename: Filename of logfile
    """

    # By default, logs all messages
    LOG = logging.getLogger(logger_name or __name__)
    LOG.setLevel(logging.DEBUG)

    # Configure console logging
    if not debug:
        cli_handler = logging.StreamHandler()
        cli_handler.setLevel(logging.DEBUG)
        cli_handler_format = logging.Formatter("%(message)s")
        cli_handler.setFormatter(cli_handler_format)
        LOG.addHandler(cli_handler)
    else:
        cli_handler = logging.StreamHandler()
        cli_handler.setLevel(logging.INFO)
        cli_handler_format = logging.Formatter(
            "%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s")
        cli_handler.setFormatter(cli_handler_format)
        LOG.addHandler(cli_handler)

    # Configure logging to file
    if log_filename:
        try:
            file_handler = logging.FileHandler(log_filename)
            file_handler.setLevel(logging.DEBUG)
            file_handler_format = logging.Formatter(
                "%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s")
            file_handler.setFormatter(file_handler_format)
            LOG.addHandler(file_handler)
            LOG.warning("Logging on file fully configured: %s" % log_filename)
        except IOError:
            LOG.warning("Unable to store log in %s" % log_filename)

    return LOG

def query_yes_no(question, default=None):
    """
    Ask a yes/no question via input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is one of "yes" or "no".
    """

    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}

    prompt = " [y/n] "

    while True:
        try:
            choice = input(f"{question} {prompt}: ").lower()
            if default is not None and choice == '':
                return valid[default]
            elif choice in valid.keys():
                return valid[choice]
        except KeyboardInterrupt as e:
            print("\nCTRL-C caught, interrupting Demo\n")
            sys.exit(1)
        except Exception:
            LOG.debug("Query failed -- EOF")
            return None