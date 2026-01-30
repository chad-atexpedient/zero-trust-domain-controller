# Contributing to Zero-Trust Domain Controller

Thank you for your interest in contributing to the Zero-Trust Domain Controller! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How to Contribute

### Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Use the issue template** when creating a new bug report
3. **Include details**:
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)
   - Logs or error messages

### Suggesting Features

1. **Check the roadmap** to see if it's already planned
2. **Open an issue** with the feature request template
3. **Describe**:
   - The problem you're trying to solve
   - Your proposed solution
   - Alternative solutions considered
   - Potential impact on existing features

### Security Vulnerabilities

**DO NOT** report security vulnerabilities through public GitHub issues.

Instead:
- Email security@example.com
- Include steps to reproduce
- Provide severity assessment
- Allow reasonable time for patching

## Development Setup

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Git
- Virtual environment tool (venv or virtualenv)

### Local Development

```bash
# Clone the repository
git clone https://github.com/chad-atexpedient/zero-trust-domain-controller.git
cd zero-trust-domain-controller

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies

# Copy environment file
cp .env.example .env
# Edit .env with your configuration

# Start dependencies
docker-compose up -d postgres redis

# Initialize the domain
python manage.py init-domain

# Run the application
python main.py
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/unit/test_auth_service.py

# Run security tests
bandit -r app/
```

## Pull Request Process

### Before Submitting

1. **Fork the repository**
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
4. **Write tests** for new functionality
5. **Ensure all tests pass**
6. **Update documentation** as needed
7. **Follow code style guidelines**

### Submitting

1. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat: add new feature"
   ```
   
   Use conventional commits:
   - `feat:` - New features
   - `fix:` - Bug fixes
   - `docs:` - Documentation changes
   - `style:` - Code style changes (formatting)
   - `refactor:` - Code refactoring
   - `test:` - Test additions or changes
   - `chore:` - Build process or auxiliary tool changes

2. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Open a Pull Request**:
   - Use the PR template
   - Reference any related issues
   - Describe your changes clearly
   - Include screenshots for UI changes

### PR Review Process

1. **Automated checks** must pass:
   - CI/CD pipeline
   - Code coverage requirements
   - Security scans
   - Linting

2. **Code review** by maintainers:
   - At least one approval required
   - Address review comments
   - Keep PR scope focused

3. **Merge**:
   - Maintainers will merge after approval
   - PR will be squash-merged to main

## Code Style Guidelines

### Python

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use [Black](https://black.readthedocs.io/) for formatting
- Use [isort](https://pycqa.github.io/isort/) for import sorting
- Maximum line length: 100 characters
- Use type hints where applicable

```bash
# Format code
black app/
isort app/

# Lint code
flake8 app/
mypy app/
```

### Documentation

- Use docstrings for all public modules, functions, classes, and methods
- Follow [Google style](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) for docstrings
- Update README.md for user-facing changes
- Add inline comments for complex logic

### Git Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit first line to 72 characters
- Reference issues and PRs liberally

## Project Structure

```
zero-trust-domain-controller/
├── app/
│   ├── api/          # API endpoints
│   ├── core/         # Core functionality
│   ├── models/       # Database models
│   ├── services/     # Business logic
│   └── utils/        # Utility functions
├── tests/
│   ├── unit/         # Unit tests
│   ├── integration/  # Integration tests
│   └── security/     # Security tests
├── k8s/              # Kubernetes manifests
├── monitoring/       # Monitoring configurations
├── docs/             # Additional documentation
└── scripts/          # Utility scripts
```

## Testing Guidelines

### Unit Tests

- Test individual functions/methods
- Mock external dependencies
- Aim for 80%+ code coverage
- Use descriptive test names

```python
def test_verify_password_with_valid_password():
    auth_service = AuthService()
    hashed = auth_service.hash_password("SecurePass123!")
    assert auth_service.verify_password("SecurePass123!", hashed)
```

### Integration Tests

- Test component interactions
- Use test database
- Clean up test data

### Security Tests

- Test authentication flows
- Verify authorization checks
- Test input validation
- Check for common vulnerabilities

## Documentation

### API Documentation

- OpenAPI/Swagger specs auto-generated from code
- Keep endpoint descriptions up to date
- Include request/response examples

### Code Documentation

```python
def calculate_risk_score(user_data: Dict, request_data: Dict) -> float:
    """
    Calculate risk score for zero-trust authentication.
    
    Args:
        user_data: Dictionary containing user's historical data
        request_data: Dictionary containing current request context
    
    Returns:
        Risk score between 0.0 (low risk) and 1.0 (high risk)
    
    Raises:
        ValueError: If required data is missing
    """
```

## Release Process

1. Version bump in `app/__init__.py`
2. Update CHANGELOG.md
3. Create release branch: `release/v1.x.x`
4. Tag release: `git tag -a v1.x.x -m "Release v1.x.x"`
5. Push tags: `git push origin v1.x.x`
6. GitHub Actions will build and publish

## Questions?

If you have questions:

1. Check the [documentation](docs/)
2. Search [existing issues](https://github.com/chad-atexpedient/zero-trust-domain-controller/issues)
3. Ask in [discussions](https://github.com/chad-atexpedient/zero-trust-domain-controller/discussions)
4. Contact maintainers

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.