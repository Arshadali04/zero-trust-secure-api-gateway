.PHONY: install dev test lint security run clean docker

install:
	pip install -r requirements.txt

dev:
	pip install -r requirements-dev.txt

run:
	uvicorn gateway.main:app --host 0.0.0.0 --port 8000 --reload

test:
	pytest tests/ -v --tb=short --cov=gateway --cov-report=term-missing

test-unit:
	pytest tests/unit/ -v --tb=short

test-integration:
	pytest tests/integration/ -v --tb=short

test-e2e:
	pytest tests/e2e/ -v --tb=short

lint:
	flake8 gateway/ tests/ --max-line-length=120 --ignore=E501,W503,E203
	isort --check-only gateway/ tests/
	mypy gateway/ --ignore-missing-imports

format:
	black gateway/ tests/
	isort gateway/ tests/

security:
	bandit -r gateway/ -ll -ii --exclude gateway/demo/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache htmlcov .coverage coverage.xml

docker:
	docker build -t zero-trust-gateway .
	docker run -p 8000:8000 zero-trust-gateway
