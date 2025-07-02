#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  build     Build the Docker image"
    echo "  start     Start the telosmiligramme server"
    echo "  stop      Stop the telosmiligramme server"
    echo "  restart   Restart the telosmiligramme server"
    echo "  logs      Show telosmiligramme logs"
    echo "  status    Show telosmiligramme status"
    echo "  clean     Clean up Docker resources"
    echo "  help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 build"
    echo "  $0 start"
    echo "  $0 logs -f"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if docker compose version &> /dev/null; then
        log_info "Using Docker Compose v2"
    elif command -v docker-compose &> /dev/null; then
        log_warning "Using legacy docker-compose. Consider upgrading to Docker Compose v2"
    else
        log_error "Docker Compose is not installed"
        exit 1
    fi
}

get_compose_cmd() {
    if docker compose version &> /dev/null; then
        echo "docker compose"
    elif command -v docker-compose &> /dev/null; then
        echo "docker-compose"
    else
        log_error "No Docker Compose found"
        exit 1
    fi
}

build_image() {
    log_info "Building Docker image..."
    COMPOSE_CMD=$(get_compose_cmd)
    $COMPOSE_CMD build --no-cache
    log_success "Docker image built successfully"
}

start_telosmiligramme() {
    log_info "Starting Telosmiligramme server..."
    
    mkdir -p logs
    touch telosmiligramme.log
    
    COMPOSE_CMD=$(get_compose_cmd)
    $COMPOSE_CMD up -d
    
    if [ $? -eq 0 ]; then
        log_success "Telosmiligramme server started successfully"
        log_info "Access telosmiligramme at: http://localhost:8080"
        log_info "To view logs: $0 logs"
        log_info "To stop: $0 stop"
    else
        log_error "Failed to start Telosmiligramme server"
        exit 1
    fi
}

stop_telosmiligramme() {
    log_info "Stopping Telosmiligramme server..."
    COMPOSE_CMD=$(get_compose_cmd)
    $COMPOSE_CMD down
    log_success "Telosmiligramme server stopped"
}

restart_telosmiligramme() {
    log_info "Restarting Telosmiligramme server..."
    stop_telosmiligramme
    sleep 2
    start_telosmiligramme
}

show_logs() {
    COMPOSE_CMD=$(get_compose_cmd)
    if [ "$2" = "-f" ] || [ "$2" = "--follow" ]; then
        log_info "Following logs (Ctrl+C to stop)..."
        $COMPOSE_CMD logs -f telosmiligramme
    else
        $COMPOSE_CMD logs telosmiligramme
    fi
}

show_status() {
    COMPOSE_CMD=$(get_compose_cmd)
    echo "Container Status:"
    $COMPOSE_CMD ps
    echo ""
    echo "Resource Usage:"
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" 2>/dev/null || echo "Unable to get stats"
}

clean_resources() {
    log_warning "This will remove all stopped containers, unused networks, and dangling images"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Cleaning up Docker resources..."
        docker system prune -f
        log_success "Cleanup completed"
    else
        log_info "Cleanup cancelled"
    fi
}

check_docker

case "${1:-help}" in
    build)
        build_image
        ;;
    start)
        start_telosmiligramme
        ;;
    stop)
        stop_telosmiligramme
        ;;
    restart)
        restart_telosmiligramme
        ;;
    logs)
        show_logs "$@"
        ;;
    status)
        show_status
        ;;
    clean)
        clean_resources
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        log_error "Unknown command: $1"
        echo ""
        show_usage
        exit 1
        ;;
esac
