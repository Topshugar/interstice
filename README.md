# Interstice

[![Interstice CI](https://github.com/Topshugar/Interstice/actions/workflows/main.yml/badge.svg)](https://github.com/Topshugar/Interstice/actions/workflows/main.yml) [![Python 3.10 | 3.11 | 3.12](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)

Find the gaps before attackers do.

Interstice is a defensive security scanner built for website owners and companies. 
It scans a domain you own, identifies common security gaps, and provides a clear,
actionable report on how to fix them.

> INTERSTICE is for authorized use only. 
> Only scan websites and infrastructure you own or have explicit written permission to test.

## Features
- Security header analysis
- HTTPS / SSL certificate validation
- Server information exposure check
- Cookie security analysis
- Common misconfiguration detection
- Plain-English remediation guidance
- HTML report with security score

## Installation
pip install requests

## Usage
python scanner.py --domain example.com --confirm-ownership

## Disclaimer
This tool is for defensive purposes. The author is not responsible for misuse.