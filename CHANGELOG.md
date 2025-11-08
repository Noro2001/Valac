# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-11-08

### Added
- Initial release of Valac - Unified Security Scanner Suite
- IP Vulnerability Scanner with Shodan InternetDB integration
- DNS to IP Resolution module
- Subdomain Enumeration (passive and brute force)
- Directory and VHost Fuzzing
- CSV Domain Extraction
- Multiple output formats (JSONL, CSV, XML, HTML)
- Interactive HTML dashboard with charts and maps
- SQLite database support for scan history
- Advanced bypass system for rate limit evasion
- Security validation and self-protection features
- Blacklist protection
- Geolocation support
- Webhook notifications for critical findings
- Comprehensive error handling
- Resource monitoring and performance optimization
- CI/CD pipeline with GitHub Actions
- Comprehensive documentation

### Fixed
- Fixed bare except statements throughout codebase
- Fixed aiodns error handling compatibility
- Fixed CSV output to include all vulnerability data
- Fixed severity score calculation
- Fixed console output visibility with progress bars
- Fixed file encoding issues
- Removed unused code (ExceptionHandler, TimeoutProtection classes)

### Changed
- Improved error handling with specific exception types
- Enhanced performance for large-scale operations
- Better resource management and monitoring
- Improved documentation and code comments

### Security
- Added security validation checks
- Added blacklist protection
- Added input validation
- Added timeout protection
- Added self-protection warnings

---

## [Unreleased]

### Planned
- Additional vulnerability databases
- More output formats
- Enhanced reporting features
- Performance improvements

