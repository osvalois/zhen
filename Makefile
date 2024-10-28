# Professional Search Toolkit Makefile

# Environment and Path Configuration
SHELL := /bin/bash
PYTHON := python3
CURDIR := $(shell pwd)
VENV := $(CURDIR)/venv
BIN := $(VENV)/bin
PYTHON_VENV := $(BIN)/python
PIP := $(BIN)/pip
PYTEST := $(BIN)/pytest
PYLINT := $(BIN)/pylint
BLACK := $(BIN)/black
PYTHON_FILES := $(shell find . -name "*.py")
SRC_DIR := $(CURDIR)/src
CONFIG_DIR := $(CURDIR)/config
DATA_DIR := $(CURDIR)/data
LOGS_DIR := $(CURDIR)/logs
EXPORTS_DIR := $(CURDIR)/exports

# Environment Variables
export PYTHONPATH := $(SRC_DIR):$(PYTHONPATH)
export VIRTUAL_ENV := $(VENV)
export PATH := $(BIN):$(PATH)

# Application Configuration
APP_NAME := search-toolkit
VERSION := $(shell cat VERSION 2>/dev/null || echo "0.1.0")
DOCKER_IMAGE := $(APP_NAME):$(VERSION)

# Colors for terminal output
CYAN := \033[0;36m
GREEN := \033[0;32m
RED := \033[0;31m
YELLOW := \033[0;33m
NC := \033[0m

.PHONY: all install clean test lint format build run docker-build docker-run help deps-check init-macos init-linux setup-dev docs benchmark security-check

all: install test lint

# Virtual Environment and Installation
$(VENV)/bin/activate: requirements.txt
	@echo "$(CYAN)Creating virtual environment...$(NC)"
	@rm -rf $(VENV)
	@$(PYTHON) -m venv $(VENV)
	@. $(VENV)/bin/activate && $(PIP) install --upgrade pip
	@. $(VENV)/bin/activate && $(PIP) install wheel setuptools
	@. $(VENV)/bin/activate && $(PIP) install -r requirements.txt
	@touch $(VENV)/bin/activate

install: $(VENV)/bin/activate

# Cleaning
clean:
	@echo "$(YELLOW)Cleaning project...$(NC)"
	@rm -rf $(VENV)
	@rm -rf build/
	@rm -rf dist/
	@rm -rf *.egg-info
	@find . -type f -name '*.pyc' -delete
	@find . -type f -name '*.pyo' -delete
	@find . -type f -name '*.pyd' -delete
	@find . -type d -name '__pycache__' -delete
	@find . -type f -name '.coverage' -delete
	@find . -type f -name 'coverage.xml' -delete
	@rm -rf .pytest_cache
	@rm -rf .mypy_cache
	@rm -rf .tox
	@rm -rf htmlcov
	@echo "$(GREEN)Clean complete!$(NC)"

# Testing and Quality
test: install
	@echo "$(CYAN)Running tests...$(NC)"
	@. $(VENV)/bin/activate && PYTHONPATH=$(SRC_DIR) $(PYTEST) \
		tests/ \
		--cov=$(SRC_DIR) \
		--cov-report=xml \
		--cov-report=term-missing \
		--cov-report=html

lint: install
	@echo "$(CYAN)Running linters...$(NC)"
	@. $(VENV)/bin/activate && $(PYLINT) $(SRC_DIR) tests/
	@. $(VENV)/bin/activate && $(BLACK) --check $(SRC_DIR) tests/
	@. $(VENV)/bin/activate && mypy $(SRC_DIR)

format: install
	@echo "$(CYAN)Formatting code...$(NC)"
	@. $(VENV)/bin/activate && $(BLACK) $(SRC_DIR) tests/
	@. $(VENV)/bin/activate && isort $(SRC_DIR) tests/

# Build and Run
build: clean install test lint
	@echo "$(CYAN)Building package...$(NC)"
	@. $(VENV)/bin/activate && $(PYTHON) setup.py sdist bdist_wheel

run:
	@if [ ! -f $(VENV)/bin/activate ]; then \
		make install; \
	fi
	@echo "$(CYAN)Starting application...$(NC)"
	@. $(VENV)/bin/activate && PYTHONPATH=$(SRC_DIR) $(PYTHON_VENV) $(SRC_DIR)/main.py

# Development Setup
setup-dev: install
	@echo "$(CYAN)Setting up development environment...$(NC)"
	@. $(VENV)/bin/activate && $(PIP) install -r requirements-dev.txt
	@. $(VENV)/bin/activate && pre-commit install
	@mkdir -p $(LOGS_DIR) $(EXPORTS_DIR)

# Docker Commands
docker-build:
	@echo "$(CYAN)Building Docker image...$(NC)"
	docker build -t $(DOCKER_IMAGE) .

docker-run:
	@echo "$(CYAN)Running in Docker container...$(NC)"
	docker run -it --rm \
		-v $(CONFIG_DIR):/app/config \
		-v $(DATA_DIR):/app/data \
		-v $(LOGS_DIR):/app/logs \
		-v $(EXPORTS_DIR):/app/exports \
		$(DOCKER_IMAGE)

# Platform-specific initialization
init-macos:
	@echo "$(CYAN)Initializing development environment for MacOS...$(NC)"
	@if ! command -v brew >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing Homebrew...$(NC)"; \
		/bin/bash -c "$$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; \
	fi
	@echo "$(CYAN)Updating Homebrew...$(NC)"
	@brew update
	@echo "$(CYAN)Installing required packages...$(NC)"
	@brew install pkg-config || true
	@brew install python@3.11 || true
	@echo "$(CYAN)Creating virtual environment...$(NC)"
	@$(PYTHON) -m venv $(VENV)
	@echo "$(CYAN)Installing dependencies...$(NC)"
	@. $(VENV)/bin/activate && $(PIP) install --upgrade pip
	@. $(VENV)/bin/activate && $(PIP) install wheel setuptools
	@. $(VENV)/bin/activate && $(PIP) install -r requirements.txt
	@mkdir -p $(LOGS_DIR) $(EXPORTS_DIR)
	@echo "$(GREEN)Setup complete! You can now run 'make run' to start the application.$(NC)"

init-linux:
	@echo "$(CYAN)Initializing development environment for Linux...$(NC)"
	@sudo apt-get update
	@sudo apt-get install -y \
		python3-dev \
		build-essential \
		pkg-config \
		python3-venv
	@make install
	@mkdir -p $(LOGS_DIR) $(EXPORTS_DIR)
	@echo "$(GREEN)Setup complete! You can now run 'make run' to start the application.$(NC)"

# Documentation
docs:
	@echo "$(CYAN)Generating documentation...$(NC)"
	@. $(VENV)/bin/activate && cd docs && make html
	@echo "$(GREEN)Documentation generated in docs/_build/html/$(NC)"

# Performance and Security
benchmark:
	@echo "$(CYAN)Running benchmarks...$(NC)"
	@. $(VENV)/bin/activate && $(PYTEST) tests/benchmark --benchmark-only

security-check:
	@echo "$(CYAN)Running security checks...$(NC)"
	@. $(VENV)/bin/activate && bandit -r $(SRC_DIR)
	@. $(VENV)/bin/activate && safety check

# Directory Structure
init-dirs:
	@mkdir -p $(SRC_DIR)
	@mkdir -p $(CONFIG_DIR)
	@mkdir -p $(DATA_DIR)
	@mkdir -p $(LOGS_DIR)
	@mkdir -p $(EXPORTS_DIR)
	@mkdir -p tests
	@mkdir -p docs

# Help
help:
	@echo "$(CYAN)Available commands:$(NC)"
	@echo "  make install        - Install dependencies"
	@echo "  make clean         - Clean build directories"
	@echo "  make test          - Run tests"
	@echo "  make lint          - Run linters"
	@echo "  make format        - Format code"
	@echo "  make build         - Build package"
	@echo "  make run           - Run application"
	@echo "  make setup-dev     - Setup development environment"
	@echo "  make init-macos    - Initialize MacOS environment"
	@echo "  make init-linux    - Initialize Linux environment"
	@echo "  make docker-build  - Build Docker image"
	@echo "  make docker-run    - Run in Docker container"
	@echo "  make docs          - Generate documentation"
	@echo "  make benchmark     - Run benchmarks"
	@echo "  make security-check- Run security checks"

# Default target
.DEFAULT_GOAL := help