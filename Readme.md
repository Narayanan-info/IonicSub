<h1 align="center">
  <a href="https://github.com/Narayanan-info/IonicSub/"><img src="assets/image-11.png" alt="Assets"></a>
</h1>

<h2 align="center">IonicSub Advanced ( 🔥 ) Powerful Subdomain Fuzzer Suite</h2>


This is a Go-based tool designed to automate the process of subdomain enumeration. It integrates multiple popular subdomain enumeration tools and techniques to gather subdomains for a given domain. The tool checks for the presence of required tools, installs them if missing, and then runs them sequentially to collect and consolidate subdomains.

## Features

- Tool Installation: Automatically checks and installs required tools if they are not already present.
- Subdomain Enumeration: Utilizes multiple tools and techniques to gather subdomains.
- Combination of Results: Combines results from various tools into a single file.
- Live Subdomain Check: Checks for live subdomains using `httpx`.

## Required Tools

The following tools are required for this script to function but its automaticaly installed once you run the tool:

- `subfinder`
- `assetfinder`
- `jq`
- `httpx`

## Installation

**Clone the Repository:**

```bash
  git clone https://github.com/Narayanan-info/IonicSub.git
  cd IonicSub
```

**Build the Go Project:**

```bash
  go build -o ionicsub main.go
```

**Run the Tool:**

```bash
  ./ionicsub example.com
```

## Usage

To run the tool, simply execute the compiled binary with the target domain as an argument:

```bash
  ./ionicsub example.com
```

## Options

- `-h, --help`: Display the help message and exit.

## Output

The tool generates the following output files:

- `subfinder_output.txt`: Subdomains found by `subfinder`.
- `assetfinder_output.txt`: Subdomains found by `assetfinder`.
- `crt_output.txt`: Subdomains found from certificate transparency logs.
- `certspotter_output.txt`: Subdomains found from Cert Spotter API.
- `all_subdomains.txt`: Combined list of all subdomains found.
- `live_subdomains.txt`: Live subdomains identified by `httpx`.

## Dependencies

- `Go` (for building and running the tool)
- `curl` (for fetching data from APIs)
- `sudo` (for installing tools via apt)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT `License` - see the LICENSE file for details.

## Acknowledgments

Thanks to all the developers of the tools used in this project.
Inspired by various subdomain enumeration techniques and scripts available in the security community.

## Disclaimer

This tool is intended for educational and ethical use only. The authors are not responsible for any misuse or damage caused by this tool. 

Always ensure you have `permission before scanning` any domain.