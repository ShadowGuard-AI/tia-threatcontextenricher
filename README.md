# tia-ThreatContextEnricher
A command-line tool that takes a single IP address, domain, or hash as input and enriches it with context from the VirusTotal API, providing a summary of known threats and classifications. The indicator is sent to VirusTotal, and the API key is sent in the x-apikey header only.

## Install
`git clone https://github.com/ShadowGuard-AI/tia-threatcontextenricher.git`

## Usage
`python3 main.py (-i <ip> | -d <domain> | -f <hash>) [-k <apikey>] [-o <output>]`

Hashes must be hex strings of length 32, 40, or 64, domains must have at least two labels with a final label of at least two letters, and IPv4 addresses must be in strict dotted-quad form: leading zeros, signs, spaces, and digit separators are rejected. Invalid input is rejected with a non-zero exit before any request is made. A VirusTotal 404 is reported as no report found. An authorization error, a rate limit, a transport failure, a non-JSON response, or an error response with no data is reported as a failed lookup with a non-zero exit and no report. If the report cannot be written to the `-o` output file, the run also exits non-zero. Requests use a 10 second timeout.

## Parameters
- `-h`: Show help message and exit
- `-i`: IP address to lookup
- `-d`: Domain to lookup
- `-f`: File hash (MD5, SHA1, SHA256) to lookup
- `-k`: VirusTotal API key. Can also be set via environment variable VIRUSTOTAL_API_KEY.
- `-o`: Output file to save the report (optional)

## License
MIT License. See LICENSE.
