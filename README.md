# Zhen Professional Search Toolkit 🔍

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Qt](https://img.shields.io/badge/Qt-6.4%2B-green.svg)](https://www.qt.io/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A professional security research toolkit that integrates Shodan and Censys search capabilities through an intuitive GUI interface, designed for efficient threat intelligence gathering and asset discovery.

## 🚀 Core Features

### Advanced Search Interface
- Modern Qt6-based graphical interface with dark theme
- Real-time query builder with syntax validation
- Template-based search system
- Multi-platform support (Windows, Linux, macOS)

### Search Capabilities
- **Shodan Integration**
  - Full support for Shodan search operators
  - Network range filtering
  - Service discovery
  - Port scanning results

- **Censys Integration**
  - Certificate analysis
  - Host discovery
  - Service enumeration
  - Autonomous system mapping

### Data Management
- SQLite database for persistent storage
- Query history tracking
- Favorite searches management
- Template system for common queries

### Analysis Tools
- Geographic distribution analysis
- Service usage statistics
- Port distribution visualization
- Basic vulnerability assessment
- Certificate chain analysis

### Automation Features
- Scheduled searches
- Automated result exports
- Email notifications
- Custom action workflows

## 🛠 Installation

### System Requirements
- Python 3.8 or higher
- Qt 6.4 or higher
- 4GB RAM minimum
- 1GB free disk space

### Dependencies Installation

```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install required packages
pip install -r requirements.txt
```

### Initial Configuration

1. Create configuration directory:
```bash
mkdir -p config
```

2. Create and configure your API keys:
```yaml
# config/config.yaml
api_keys:
  shodan: "your-shodan-api-key"
  censys_id: "your-censys-api-id"
  censys_secret: "your-censys-api-secret"
```

## 💻 Usage Guide

### Starting the Application

```bash
python main.py
```

### Basic Search Workflow

1. **Select Search Platform**
   - Choose between Shodan or Censys
   - Each platform has optimized search fields

2. **Build Your Query**
   - Use the query builder interface
   - Select from predefined filters
   - Combine multiple search criteria

3. **Execute Search**
   - Click "Search" to execute
   - View results in real-time
   - Access detailed result analysis

4. **Manage Results**
   - Export in multiple formats (CSV, JSON, Excel)
   - Save interesting queries
   - Create custom templates

### Template System

The toolkit includes a template management system for common searches:

- Network scanning templates
- Service discovery templates
- Vulnerability assessment templates
- Custom template creation

### Analysis Features

- Geographic distribution maps
- Service usage statistics
- Port distribution charts
- Timeline analysis
- Basic vulnerability correlation

## 🔧 Development

### Setup Development Environment

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Check code style
black .
flake8 .
```

### Project Structure

```
search-toolkit/
├── config/         # Configuration files
├── data/          # Database and data files
├── docs/          # Documentation
├── exports/       # Export directory
├── logs/          # Log files
├── src/           # Source code
├── tests/         # Test files
└── main.py        # Main application entry
```

## 📚 Documentation

Comprehensive documentation is available in the `docs/` directory:

- [User Guide](docs/user-guide.md)
- [API Configuration](docs/api-configuration.md)
- [Template System](docs/templates.md)
- [Analysis Tools](docs/analysis.md)

## 🤝 Contributing

Contributions are welcome! Please read our contribution guidelines before submitting pull requests.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for legitimate security research and asset management. Users are responsible for ensuring compliance with applicable laws and regulations.

## 🔄 Updates

Check the [CHANGELOG.md](CHANGELOG.md) for version updates and changes.

---
Built by Security Researchers for Security Researchers 🛡️