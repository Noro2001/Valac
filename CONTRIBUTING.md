# Contributing to Valac

Thank you for your interest in contributing to Valac! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Report bugs and suggest improvements

## Getting Started

1. **Fork the repository**
2. **Clone your fork:**
   ```bash
   git clone https://github.com/your-username/Valac.git
   cd valac
   ```

3. **Create a branch:**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```

4. **Set up development environment:**
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

## Development Guidelines

### Code Style

- Follow PEP 8 style guide
- Maximum line length: 127 characters
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Comment complex logic

### Commit Messages

Use clear, descriptive commit messages:

```
feat: Add new feature for X
fix: Fix bug in Y module
docs: Update README with installation instructions
refactor: Improve code structure in Z
test: Add tests for feature X
```

### Testing

- Test your changes before submitting
- Ensure all existing tests pass
- Add tests for new features when possible
- Test on multiple platforms if possible (Windows, Linux, macOS)

### Pull Request Process

1. **Update documentation** if you've changed functionality
2. **Add tests** for new features or bug fixes
3. **Ensure code passes linting** (flake8, pylint)
4. **Update CHANGELOG.md** if applicable
5. **Submit PR** with clear description

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Code is commented where necessary
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests pass locally
- [ ] Changes tested manually

## Reporting Bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) and include:

- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version)
- Error messages/logs

## Suggesting Features

Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md) and include:

- Clear description of the feature
- Use case or problem it solves
- Proposed solution
- Alternatives considered

## Code Review

- All PRs require review before merging
- Be open to feedback and suggestions
- Address review comments promptly
- Keep PRs focused and reasonably sized

## Questions?

- Open an issue for questions
- Check existing issues and PRs first
- Be patient - maintainers are volunteers

Thank you for contributing to Valac! 🎉

