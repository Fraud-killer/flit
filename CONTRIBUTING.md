# Contributing to FLIT

Thank you for your interest in contributing to FLIT! We welcome contributions from the community.

## Getting Started

### Prerequisites

- Python 3.11+
- PostgreSQL 14+
- Redis 6+
- Docker (optional, for containerized development)

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/flit.git
   cd flit
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   cd app
   pip install pipenv
   pipenv install --dev
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your local settings
   ```

5. **Run migrations**
   ```bash
   python manage.py migrate
   ```

6. **Run the development server**
   ```bash
   python manage.py runserver
   ```

### Running Tests

```bash
# Run all tests
python run_tests.py

# Run specific test file
pytest tests/unit/test_fraud_rules.py -v

# Run with coverage
pytest --cov=app tests/
```

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/your-org/flit/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the feature and its use case
3. Explain why it would benefit FLIT users

### Submitting Pull Requests

1. **Fork the repository** and create your branch from `main`
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

3. **Run tests** to ensure nothing is broken
   ```bash
   python run_tests.py
   ```

4. **Commit your changes**
   ```bash
   git commit -m "feat: add your feature description"
   ```
   
   We follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` new feature
   - `fix:` bug fix
   - `docs:` documentation only
   - `test:` adding tests
   - `refactor:` code refactoring
   - `chore:` maintenance tasks

5. **Push and create a Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

### Code Style

- Follow PEP 8 for Python code
- Use type hints where possible
- Keep functions focused and small
- Write docstrings for public functions and classes

### Adding New Fraud Rules

FLIT's power comes from its extensible rule system. To add a new rule:

1. Create a new file in `app/core/audit/rules/`
2. Extend `BaseRule` class
3. Implement the `_evaluate` method
4. Register the rule in `app/core/audit/rules/__init__.py`
5. Add the rule to `Auditor.rule_classes` in `app/core/audit/auditor.py`
6. Write unit tests in `tests/unit/test_fraud_rules.py`

Example:
```python
from .base_rule import BaseRule

class MyNewRule(BaseRule):
    code = "my_new_rule"
    weight = 0.7  # 0.0 to 1.0
    
    async def _evaluate(self, event, policy):
        # Your detection logic here
        if suspicious_condition:
            self.add_message("Suspicious activity detected", score=0.8)
```

## Community

- **Discussions**: Use GitHub Discussions for questions and ideas
- **Security Issues**: Report security vulnerabilities privately to security@flit.io

## License

By contributing to FLIT, you agree that your contributions will be licensed under the MIT License.

---

<p align="center">
  <strong>Thank you for helping protect money in motion!</strong>
</p>
