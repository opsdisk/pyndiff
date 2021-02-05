#!/usr/bin/env python
# Standard Python libraries.
import sys

# Custom Python libraries.
import pyndiff


def main():
    args = pyndiff.parse_args()
    pyndiff.generate_diff(**vars(args))

    return 0


if __name__ == "__main__":
    sys.exit(main())
