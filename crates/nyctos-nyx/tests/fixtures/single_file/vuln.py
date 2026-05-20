# Fixture for the nyctos-nyx subprocess driver integration test.
#
# This file is intentionally vulnerable. It exists only as a deterministic
# input for `nyx scan`: a tainted-stdin -> eval flow that every supported
# `nyx` version should report at least once. Do not import it anywhere; do
# not promote it into a sample app.

import os
import sys


def main() -> None:
    user_input = sys.stdin.read()
    # Classic code-injection sink: eval over attacker-controlled input.
    eval(user_input)  # noqa: S307

    # Classic command-injection sink: shell=True over tainted argv.
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    os.system(f"echo {cmd}")


if __name__ == "__main__":
    main()
