# Overview

`pyndiff` (pronounced pin-diff) easily generates human-readable [ndiff](https://nmap.org/book/ndiff-man.html)
output when comparing 2 Nmap XML scan files.  It is great for determining what ports have open/closed or had their
services change between Nmap scans and presenting it in a visually appealing and consumable way for humans.
Unfortunately, both the diff and XML output from `ndiff` are unreadable and unusable for a large number of targets with
many changes.  `pyndiff` has been used to compare two different 40 MB Nmap XML files in 13 seconds!

This library is used in [Scantron](https://github.com/rackerlabs/scantron/), the distributed Nmap / masscan scanning
framework, to email out Nmap scan diffs (coming soon!).

`pyndiff` is developed and maintained by [@opsdisk](https://twitter.com/opsdisk) as part of Rackspace's Threat and
Vulnerability Analysis team.

## What is ndiff?

<https://nmap.org/book/ndiff-man.html>

```none
Ndiff is a tool to aid in the comparison of Nmap scans. It takes two Nmap XML output files and prints the differences
between them. The differences observed are:

* Host states (e.g. up to down)
* Port states (e.g. open to closed)
* Service versions (from -sV)
* OS matches (from -O)
* Script output

Ndiff, like the standard diff utility, compares two scans at a time.
```

## Installation

Using pip:

```bash
pip install pyndiff
```

From GitHub:

```bash
git clone https://github.com/rackerlabs/pyndiff.git
cd pyndiff
virtualenv -p python3.6 .venv  # If using a virtual environment.
source .venv/bin/activate  # If using a virtual environment.
python setup.py install
```

## Notes

See Nmap's [PR-1807](<https://github.com/nmap/nmap/pull/1807>) for a Python3 compatible `ndiff`.
Until [PR-1807](<https://github.com/nmap/nmap/pull/1807>) is merged into master, the individual ndiff.py found below is
used:

<https://github.com/nmap/nmap/pull/1807/files#diff-876b1aeeb590be439b50702351985b633655e89e78f6b520f321ce84076c6b32>

## Helpful Options

`--uof` - Optionally ignore UDP "open|filtered" port state changes because they aren't definitive.

`-d` - Stop processing after every diff to validate results only when the `-v` switch is used.

`-v` - Print verbose data for troubleshooting. Helpful when used in with `-d`

## Run as script

### Human readable

Generate a human-readable overview of the changes.

```bash
pyndiff -f1 test-scans/random-1.xml -f2 test-scans/random-2.xml
```

![pyndiff_script.png](images/pyndiff_script.png)

### Classic text output

Classic `ndiff --text` output, not human-readable for large scans.

```bash
pyndiff -f1 test-scans/random-1.xml -f2 test-scans/random-2.xml -t txt
```

![pyndiff_script_classic.png](images/pyndiff_script_classic.png)

## pyndiff as a module

```python
import pyndiff

# XML
diff = pyndiff.generate_diff("test-scans/random-1.xml", "test-scans/random-2.xml", ignore_udp_open_filtered=False)

print(diff)

# TXT
diff = pyndiff.generate_diff(
    "test-scans/random-1.xml",
    "test-scans/random-2.xml",
    ignore_udp_open_filtered=False,
    output_type="txt"
)

print(diff)
```

![pyndiff_module.png](images/pyndiff_module.png)

## test-scans directory

The `test-scans` directory contains the same test scans found in Nmap's repo found here:

<https://github.com/nmap/nmap/tree/master/ndiff/test-scans>

## Support

This code is supplied as-is and you should not expect to receive support for it.  Use it at your own risk.

## License

License is Apache License Version 2.0.
