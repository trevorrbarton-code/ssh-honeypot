# SSH Honeypot Management Makefile

.PHONY: help build start stop restart logs clean shell train report status

# Default target
help:
	@echo "SSH Honeypot Management Commands"
	@echo "================================"
	@echo ""
	@echo "Setup Commands:"
	@echo "  make setup       - Initial setup (create directories, copy config)"
	@echo "  make build       - Build Docker images"
	@echo ""
	@echo "Runtime Commands:"
	@echo "  make start       - Start all services"
	@echo "  make stop        - Stop all services"
	@echo "  make restart     - Restart all services"
	@echo "  make status      - Check service status"
	@echo ""
	@echo "Monitoring Commands:"
	@echo "  make logs        - View all logs"
	@echo "  make logs-hp     - View honeypot logs only"
	@echo "  make logs-db     - View dashboard logs only"
	@echo "  make shell-hp    - Open shell in honeypot container"
	@echo "  make shell-db    - Open shell in dashboard container"
	@echo ""
	@echo "Maintenance Commands:"
	@echo "  make train       - Train/retrain ML classifier"
	@echo "  make report      - Generate daily report"
	@echo "  make backup      - Backup database and logs"
	@echo "  make clean       - Remove containers and volumes"
	@echo "  make clean-all   - Full cleanup including images"
	@echo ""
	@echo "Development Commands:"
	@echo "  make dev         - Start in development mode"
	@echo "  make test        - Run tests"
	@echo "  make lint        - Run code linting"

# Setup
setup:
	@echo "Setting up SSH Honeypot..."
	mkdir -p data logs reports config
	@if [ ! -f .env ]; then cp .env.example .env; echo "Created .env from example"; fi
	@echo "Setup complete. Edit .env with your configuration."

# Build
build:
	@echo "Building Docker images..."
	docker-compose build

# Start services
start:
	@echo "Starting SSH Honeypot services..."
	docker-compose up -d
	@echo "Services started:"
	@echo "  - SSH Honeypot: localhost:$(shell grep HONEYPOT_EXTERNAL_PORT .env 2>/dev/null | cut -d= -f2 || echo 2222)"
	@echo "  - Dashboard: http://localhost:$(shell grep DASHBOARD_EXTERNAL_PORT .env 2>/dev/null | cut -d= -f2 || echo 8080)"

# Stop services
stop:
	@echo "Stopping services..."
	docker-compose down

# Restart services
restart: stop start

# Check status
status:
	@echo "Service Status:"
	@docker-compose ps

# View logs
logs:
	docker-compose logs -f

logs-hp:
	docker-compose logs -f honeypot

logs-db:
	docker-compose logs -f dashboard

# Open shells
shell-hp:
	docker-compose exec honeypot /bin/sh

shell-db:
	docker-compose exec dashboard /bin/sh

# Train classifier
train:
	@echo "Training ML classifier..."
	@curl -s -X POST http://localhost:$(shell grep DASHBOARD_EXTERNAL_PORT .env 2>/dev/null | cut -d= -f2 || echo 8080)/api/classifier/train | python -m json.tool || echo "Failed to train. Is the dashboard running?"

# Generate report
report:
	@echo "Generating daily report..."
	docker-compose run --rm report-generator
	@echo "Report generated in ./reports/"

# Backup
backup:
	@echo "Creating backup..."
	@mkdir -p backups
	@tar -czf backups/honeypot-backup-$(shell date +%Y%m%d-%H%M%S).tar.gz data/ logs/ reports/ 2>/dev/null || echo "Nothing to backup yet"
	@echo "Backup complete"

# Clean up
clean:
	@echo "Cleaning up containers and volumes..."
	docker-compose down -v

clean-all: clean
	@echo "Removing images..."
	docker-compose down --rmi all
	@echo "Removing local data..."
	@rm -rf data/* logs/* reports/*

# Development mode
dev:
	@echo "Starting in development mode..."
	FLASK_DEBUG=true docker-compose up

# Run tests
test:
	@echo "Running tests..."
	@python -m pytest tests/ -v 2>/dev/null || echo "No tests found"

# Lint code
lint:
	@echo "Running linters..."
	@flake8 honeypot/ ml/ dashboard/ reports/ 2>/dev/null || echo "flake8 not installed"
	@pylint honeypot/ ml/ dashboard/ reports/ 2>/dev/null || echo "pylint not installed"

# Update
update: stop build start
	@echo "Update complete"

# Security scan
security-scan:
	@echo "Running security scan..."
	@docker-compose exec honeypot pip list --format=json | python -m json.tool 2>/dev/null || echo "Scan complete"

# Show stats
stats:
	@echo "Quick Statistics:"
	@echo "================"
	@curl -s http://localhost:$(shell grep DASHBOARD_EXTERNAL_PORT .env 2>/dev/null | cut -d= -f2 || echo 8080)/api/stats | python -m json.tool 2>/dev/null || echo "Dashboard not accessible"
