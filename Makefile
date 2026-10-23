# CloudPatrol developer tasks.
#
# Every target is safe to run repeatedly. Nothing here touches AWS or a
# deployed environment; the db-* targets act only on a local container.

.PHONY: help install install-api install-web test test-api test-web \
        lint lint-api lint-web typecheck typecheck-api typecheck-web \
        fmt fmt-api fmt-web check build dev-api dev-web \
        db-up db-down db-apply db-seed

API_DIR := services/api
WEB_DIR := apps/web
API_PY  := $(API_DIR)/.venv/bin/python
DB_NAME := cloudpatrol-pg

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# --- setup -----------------------------------------------------------------
install: install-api install-web ## Install all dependencies

install-api: ## Create the API virtualenv and install dev dependencies
	python -m venv $(API_DIR)/.venv
	$(API_PY) -m pip install --upgrade pip
	$(API_PY) -m pip install -e "$(API_DIR)[dev]"

install-web: ## Install web dependencies
	cd $(WEB_DIR) && npm ci

# --- tests -----------------------------------------------------------------
test: test-api test-web ## Run every test suite

test-api: ## Run API tests
	cd $(API_DIR) && .venv/bin/pytest -q

test-web: ## Run web tests
	cd $(WEB_DIR) && npm test

# --- quality ---------------------------------------------------------------
lint: lint-api lint-web ## Lint everything

lint-api: ## Ruff lint
	cd $(API_DIR) && .venv/bin/ruff check .

lint-web: ## ESLint
	cd $(WEB_DIR) && npm run lint

fmt: fmt-api ## Format everything

fmt-api: ## Ruff format
	cd $(API_DIR) && .venv/bin/ruff format .

typecheck: typecheck-api typecheck-web ## Type-check everything

typecheck-api: ## Mypy
	cd $(API_DIR) && .venv/bin/mypy app

typecheck-web: ## tsc
	cd $(WEB_DIR) && npm run typecheck

check: lint typecheck test build ## Everything CI runs

build: ## Production build of the web app
	cd $(WEB_DIR) && npm run build

# --- local services --------------------------------------------------------
dev-api: ## Run the API with reload on :8000
	# The app is built by a factory, so --factory is required.
	cd $(API_DIR) && .venv/bin/uvicorn --factory app.main:create_app --reload --port 8000

dev-web: ## Run the web app on :3000
	cd $(WEB_DIR) && npm run dev

# --- database --------------------------------------------------------------
# The migration depends on auth.users and auth.uid(), which Supabase provides.
# Against plain PostgreSQL these must be stubbed first, or the memberships
# foreign key fails. That is expected, not a defect in the migration.
db-up: ## Start a local PostgreSQL container
	docker run -d --name $(DB_NAME) \
	  -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=postgres \
	  postgres:16-alpine
	@until docker exec $(DB_NAME) pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
	@echo "PostgreSQL ready on :5432"

db-down: ## Stop and remove the local PostgreSQL container
	-docker rm -f $(DB_NAME)

db-apply: ## Apply every migration to the local container, in order
	@for f in supabase/migrations/*.sql; do \
	  echo "applying $$f"; \
	  docker exec -i $(DB_NAME) psql -U postgres -d postgres -v ON_ERROR_STOP=1 < "$$f" || exit 1; \
	done

db-seed: ## Insert demo data (requires an auth user to exist)
	docker exec -i $(DB_NAME) psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
	  < supabase/seed.sql
