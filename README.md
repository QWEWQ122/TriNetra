# TriNetra 🕵️‍♂️

![TriNetra](https://img.shields.io/badge/TriNetra-v1.0.0-blue.svg) ![Python](https://img.shields.io/badge/Python-3.8%2B-yellow.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg)

TriNetra is a fast web reconnaissance tool designed to uncover hidden endpoints, API keys, and tokens. Built for bug hunters and OSINT professionals, it features Tor support and provides rich command-line interface (CLI) output. Whether you are looking to enhance your bug bounty skills or streamline your reconnaissance efforts, TriNetra offers the tools you need.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Command Line Options](#command-line-options)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Features 🚀

- **Fast and Efficient**: TriNetra quickly scans web applications for vulnerabilities.
- **Hidden Endpoint Discovery**: Uncover endpoints that are not easily visible.
- **API Key and Token Detection**: Identify sensitive information in your target applications.
- **Tor Support**: Conduct your reconnaissance anonymously.
- **Rich CLI Output**: Get detailed results in an easy-to-read format.
- **Cross-Platform Compatibility**: Works on Windows, macOS, and Linux.

## Installation 🛠️

To get started with TriNetra, download the latest release from our [Releases section](https://github.com/QWEWQ122/TriNetra/releases). Make sure to download the appropriate file for your operating system. After downloading, follow the instructions below to set up the tool.

### Step 1: Download

Visit the [Releases section](https://github.com/QWEWQ122/TriNetra/releases) to download the latest version of TriNetra.

### Step 2: Install Dependencies

Make sure you have Python 3.8 or higher installed on your system. You can check your Python version by running:

```bash
python --version
```

If you need to install Python, visit [python.org](https://www.python.org/downloads/) for the latest version.

### Step 3: Install Required Libraries

Navigate to the directory where you downloaded TriNetra and run:

```bash
pip install -r requirements.txt
```

This command will install all necessary libraries for TriNetra to function properly.

## Usage 📖

To run TriNetra, open your terminal and navigate to the directory where you installed it. Use the following command:

```bash
python trinetra.py [options] <target>
```

Replace `<target>` with the URL of the web application you want to scan. You can also specify various options to customize your scan.

## Command Line Options ⚙️

TriNetra provides several command-line options to tailor your reconnaissance:

- `-h`, `--help`: Show help message and exit.
- `-t`, `--tor`: Use Tor for anonymous scanning.
- `-o`, `--output`: Specify an output file to save results.
- `-v`, `--verbose`: Enable verbose output for detailed results.

### Example Command

To scan a target using Tor and save the results to a file, use:

```bash
python trinetra.py -t -o results.txt http://example.com
```

## Contributing 🤝

We welcome contributions from the community! If you want to help improve TriNetra, follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your branch to your forked repository.
5. Create a pull request.

Please ensure that your code follows our coding standards and includes appropriate tests.

## License 📜

TriNetra is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

## Support 🆘

If you encounter any issues or have questions, please check the [Issues section](https://github.com/QWEWQ122/TriNetra/issues) on GitHub. You can also reach out via our community forums or email.

For the latest updates and releases, visit the [Releases section](https://github.com/QWEWQ122/TriNetra/releases). Download the latest version and execute the appropriate file for your operating system.

---

Thank you for using TriNetra! Happy hunting! 🕵️‍♀️