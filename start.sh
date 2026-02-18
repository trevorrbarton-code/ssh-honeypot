#!/bin/bash
#
# SSH Honeypot Startup Script
# 
# This script handles the initialization and startup of the SSH honeypot
# with proper safety checks and configuration validation.

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Functions
print_banner() {
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║              SSH Honeypot Startup Script                   ║"
    echo "║         Medium-Interaction Honeypot with ML Analytics      ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_error() {
    echo -e "${RED}ERROR: $1${NC}" >&2
}

print_warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
}

print_success() {
    echo -e "${GREEN}SUCCESS: $1${NC}"
}

print_info() {
    echo -e "INFO: $1"
}

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if Docker is running
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Setup environment
setup_environment() {
    print_info "Setting up environment..."
    
    # Create necessary directories
    mkdir -p data logs reports config
    
    # Copy environment file if it doesn't exist
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            cp .env.example .env
            print_warning "Created .env from .env.example. Please review and customize it."
        else
            print_error ".env.example not found. Cannot create configuration."
            exit 1
        fi
    fi
    
    # Source environment variables
    set -a
    source .env
    set +a
    
    print_success "Environment setup complete"
}

# Validate configuration
validate_config() {
    print_info "Validating configuration..."
    
    # Check if ports are available
    HONEYPOT_PORT=${HONEYPOT_EXTERNAL_PORT:-2222}
    DASHBOARD_PORT=${DASHBOARD_EXTERNAL_PORT:-8080}
    
    if lsof -Pi :$HONEYPOT_PORT -sTCP:LISTEN -t &> /dev/null; then
        print_warning "Port $HONEYPOT_PORT is already in use. SSH Honeypot may fail to start."
    fi
    
    if lsof -Pi :$DASHBOARD_PORT -sTCP:LISTEN -t &> /dev/null; then
        print_warning "Port $DASHBOARD_PORT is already in use. Dashboard may fail to start."
    fi
    
    # Check Flask secret key
    if grep -q "FLASK_SECRET_KEY=change-me-in-production" .env 2>/dev/null || \
       grep -q "FLASK_SECRET_KEY=your-super-secret-key" .env 2>/dev/null; then
        print_warning "Default Flask secret key detected. Please change it in .env for security."
    fi
    
    print_success "Configuration validation complete"
}

# Display warnings
display_warnings() {
    echo ""
    print_warning "SECURITY WARNINGS"
    echo "================"
    echo "This honeypot is designed to attract and log malicious SSH activity."
    echo ""
    echo "Before continuing, ensure:"
    echo "  1. You have authorization to deploy this on your network"
    echo "  2. The honeypot is isolated from production systems"
    echo "  3. You understand the legal implications in your jurisdiction"
    echo "  4. You have proper monitoring and incident response procedures"
    echo ""
    echo "For more information, see README.md"
    echo ""
}

# Ask for confirmation
confirm_deployment() {
    if [ "$SKIP_CONFIRM" = "true" ]; then
        return 0
    fi
    
    read -p "Do you want to continue? (yes/no): " response
    if [[ ! "$response" =~ ^[Yy][Ee][Ss]$ ]]; then
        print_info "Deployment cancelled by user"
        exit 0
    fi
}

# Build images
build_images() {
    print_info "Building Docker images..."
    docker-compose build
    print_success "Build complete"
}

# Start services
start_services() {
    print_info "Starting services..."
    docker-compose up -d
    print_success "Services started"
}

# Wait for services
wait_for_services() {
    print_info "Waiting for services to be ready..."
    
    HONEYPOT_PORT=${HONEYPOT_EXTERNAL_PORT:-2222}
    DASHBOARD_PORT=${DASHBOARD_EXTERNAL_PORT:-8080}
    
    # Wait for honeypot
    for i in {1..30}; do
        if nc -z localhost $HONEYPOT_PORT 2>/dev/null; then
            print_success "SSH Honeypot is ready on port $HONEYPOT_PORT"
            break
        fi
        sleep 1
    done
    
    # Wait for dashboard
    for i in {1..30}; do
        if curl -s http://localhost:$DASHBOARD_PORT &> /dev/null; then
            print_success "Dashboard is ready on port $DASHBOARD_PORT"
            break
        fi
        sleep 1
    done
}

# Display status
display_status() {
    echo ""
    print_success "SSH Honeypot is now running!"
    echo ""
    echo "Access Information:"
    echo "=================="
    echo "SSH Honeypot: localhost:${HONEYPOT_EXTERNAL_PORT:-2222}"
    echo "Dashboard:    http://localhost:${DASHBOARD_EXTERNAL_PORT:-8080}"
    echo ""
    echo "Useful Commands:"
    echo "==============="
    echo "View logs:    make logs"
    echo "Stop:         make stop"
    echo "Restart:      make restart"
    echo "Train ML:     make train"
    echo "Generate report: make report"
    echo ""
    echo "For more options, run: make help"
    echo ""
}

# Main execution
main() {
    print_banner
    
    # Check for skip confirm flag
    SKIP_CONFIRM=${SKIP_CONFIRM:-false}
    
    # Run setup steps
    check_prerequisites
    setup_environment
    validate_config
    display_warnings
    confirm_deployment
    build_images
    start_services
    wait_for_services
    display_status
}

# Handle command line arguments
case "${1:-}" in
    --skip-confirm)
        SKIP_CONFIRM=true
        main
        ;;
    --stop)
        print_info "Stopping services..."
        docker-compose down
        print_success "Services stopped"
        ;;
    --restart)
        print_info "Restarting services..."
        docker-compose restart
        print_success "Services restarted"
        ;;
    --status)
        docker-compose ps
        ;;
    --logs)
        docker-compose logs -f
        ;;
    --help|-h)
        echo "SSH Honeypot Startup Script"
        echo ""
        echo "Usage: $0 [OPTION]"
        echo ""
        echo "Options:"
        echo "  --skip-confirm    Skip confirmation prompt"
        echo "  --stop            Stop all services"
        echo "  --restart         Restart all services"
        echo "  --status          Show service status"
        echo "  --logs            View logs"
        echo "  --help, -h        Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  SKIP_CONFIRM=true    Skip confirmation (same as --skip-confirm)"
        echo ""
        ;;
    *)
        main
        ;;
esac
