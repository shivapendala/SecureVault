.PHONY: help install run dev init-db test test-verbose lint format clean docker-build docker-up docker-down

help:
	@echo "SecureVault Platform Build & Automation Commands:"
	@echo "  make install       - Install production and test dependencies"
	@echo "  make init-db       - Initialize and seed MySQL database schema"
	@echo "  make run           - Run the SecureVault server on http://localhost:5005"
	@echo "  make test          - Run full pytest automated security test suite"
	@echo "  make test-verbose  - Run pytest with verbose trace output"
	@echo "  make lint          - Run code quality and syntax linters"
	@echo "  make docker-build  - Build production Docker image"
	@echo "  make docker-up     - Start application and MySQL containers via Docker Compose"
	@echo "  make docker-down   - Stop running Docker Compose containers"

install:
	pip install -r requirements.txt

init-db:
	python init_db.py

run:
	python run.py

dev:
	python run.py

test:
	python -m pytest

test-verbose:
	python -m pytest -v

lint:
	python -m flake8 app/ tests/ || true

format:
	python -m black app/ tests/ || true

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .coverage htmlcov/

docker-build:
	docker build -t securevault-app:latest .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down
