.PHONY: help install dev test lint format scan tf-validate clean all

PYTHON := python3
PIP := pip
SRC := src
TESTS := tests
INFRA := infra

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install project dependencies
	$(PIP) install -e .

dev: ## Install with development dependencies
	$(PIP) install -e ".[dev]"
	pre-commit install

test: ## Run test suite
	pytest $(TESTS) -v --tb=short

test-cov: ## Run tests with coverage report
	pytest $(TESTS) -v --tb=short --cov=$(SRC) --cov-report=term-missing --cov-report=html

lint: ## Run linting checks
	ruff check $(SRC) $(TESTS)
	ruff format --check $(SRC) $(TESTS)

format: ## Auto-format code
	ruff format $(SRC) $(TESTS)
	ruff check --fix $(SRC) $(TESTS)

typecheck: ## Run type checking
	mypy $(SRC)

scan: ## Run security scans
	bandit -r $(SRC) -c pyproject.toml
	@echo "---"
	@echo "Security scan complete."

scan-all: ## Run all security tools (bandit + ruff security rules)
	bandit -r $(SRC) -c pyproject.toml
	ruff check $(SRC) --select S
	@echo "---"
	@echo "Full security scan complete."

tf-validate: ## Validate all Terraform configurations
	@for dir in $(shell find $(INFRA) -name "*.tf" -exec dirname {} \; | sort -u); do \
		echo "Validating $$dir..."; \
		cd $$dir && terraform init -backend=false > /dev/null 2>&1 && terraform validate && cd - > /dev/null; \
	done

tf-fmt: ## Format Terraform files
	terraform fmt -recursive $(INFRA)

clean: ## Clean build artifacts and caches
	rm -rf build/ dist/ *.egg-info .eggs/
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/
	rm -rf htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned."

all: lint typecheck test scan ## Run all checks (lint + typecheck + test + scan)
	@echo "All checks passed."
