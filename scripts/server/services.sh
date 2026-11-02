#!/bin/bash
# Starts, stops and inspects the server-side services of the test bench.
#
#   services.sh up       [db|monitor|deploy|all]   start (default: all)
#   services.sh down     [db|monitor|deploy|all]   stop (the database container is stopped, its data is kept)
#   services.sh restart  [db|monitor|deploy|all]
#   services.sh status
#   services.sh rotate-logs                        move the serial logs of the devices to logs/archive/<timestamp>
#   services.sh reset-db                           drop the database volume and start an empty database
#
# The Python services run in detached tmux sessions (sraft-monitor, sraft-deploy); their output is
# also appended to run/monitor.out and run/deploy.out.

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_DIR="$DIR/run"
LOG_DIR="$DIR/logs"
PY="$DIR/venv/bin/python"
CONTAINER="pg_server"
mkdir -p "$RUN_DIR" "$LOG_DIR"

# Credentials (POSTGRES_PASSWORD, DATABASE_URL) are read from scripts/server/.env, which is gitignored.
if [ -f "$DIR/.env" ]; then
    set -a
    . "$DIR/.env"
    set +a
fi

port_open() { ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$1\$"; }

wait_port() {
    local port=$1 timeout=${2:-30}
    for _ in $(seq "$timeout"); do
        port_open "$port" && return 0
        sleep 1
    done
    return 1
}

proc_running() { pgrep -f "python[0-9.]* (-u )?$1" >/dev/null; }

db_up() {
    if [ "$(docker ps -q -f name=^${CONTAINER}$)" ]; then
        echo "db: already running"
    elif [ "$(docker ps -aq -f name=^${CONTAINER}$)" ]; then
        docker start "$CONTAINER" >/dev/null && echo "db: started (existing container)"
    else
        (cd "$DIR" && ./start_postgres.sh >/dev/null) && echo "db: started (new container)"
    fi
    for _ in $(seq 30); do
        docker exec "$CONTAINER" pg_isready -U raft >/dev/null 2>&1 && { echo "db: ready"; return 0; }
        sleep 1
    done
    echo "db: NOT ready" >&2
    return 1
}

db_down() {
    if [ "$(docker ps -q -f name=^${CONTAINER}$)" ]; then
        docker stop "$CONTAINER" >/dev/null && echo "db: stopped"
    else
        echo "db: not running"
    fi
}

svc_up() {
    local name=$1 script=$2 port=$3
    if proc_running "$script"; then
        echo "$name: already running"
        return 0
    fi
    tmux kill-session -t "sraft-$name" 2>/dev/null
    echo "===== $(date '+%F %T') start =====" >> "$RUN_DIR/$name.out"
    # The session inherits the environment of the tmux server, not of this script: the credentials
    # are loaded again inside it.
    tmux new-session -d -s "sraft-$name" \
        "cd '$DIR' && if [ -f .env ]; then set -a; . ./.env; set +a; fi; '$PY' -u $script 2>&1 | tee -a '$RUN_DIR/$name.out'"
    if wait_port "$port" 60; then
        echo "$name: up on port $port"
    else
        echo "$name: FAILED to open port $port, last output:" >&2
        tail -20 "$RUN_DIR/$name.out" >&2
        return 1
    fi
}

svc_down() {
    local name=$1 script=$2
    if ! proc_running "$script"; then
        tmux kill-session -t "sraft-$name" 2>/dev/null
        echo "$name: not running"
        return 0
    fi
    pkill -INT -f "python[0-9.]* (-u )?$script"
    for _ in $(seq 15); do
        proc_running "$script" || break
        sleep 1
    done
    proc_running "$script" && pkill -KILL -f "python[0-9.]* (-u )?$script"
    tmux kill-session -t "sraft-$name" 2>/dev/null
    echo "$name: stopped"
}

monitor_up()   { svc_up monitor monitoring_server.py 9002; }
monitor_down() { svc_down monitor monitoring_server.py; }
deploy_up()    { svc_up deploy server_deploy.py 8000; }
deploy_down()  { svc_down deploy server_deploy.py; }

status() {
    if [ "$(docker ps -q -f name=^${CONTAINER}$)" ]; then echo "db: running"; else echo "db: stopped"; fi
    for pair in "monitor monitoring_server.py 9002" "deploy server_deploy.py 8000"; do
        set -- $pair
        if proc_running "$2"; then
            if port_open "$3"; then echo "$1: running (port $3 open)"; else echo "$1: running (port $3 NOT open)"; fi
        else
            echo "$1: stopped"
        fi
    done
    echo "devices: $(ls /dev/ttyUSB* 2>/dev/null | wc -l) serial ports"
}

rotate_logs() {
    local files
    files=$(ls "$LOG_DIR"/*.log 2>/dev/null)
    if [ -z "$files" ]; then
        echo "logs: nothing to rotate"
        return 0
    fi
    local dest="$LOG_DIR/archive/$(date '+%Y%m%d_%H%M%S')"
    mkdir -p "$dest"
    mv "$LOG_DIR"/*.log "$dest"/
    echo "logs: moved to $dest"
}

action=${1:-status}
target=${2:-all}

case "$action" in
    up)
        case "$target" in
            db) db_up ;; monitor) monitor_up ;; deploy) deploy_up ;;
            all) db_up && monitor_up && deploy_up ;;
        esac ;;
    down)
        case "$target" in
            db) db_down ;; monitor) monitor_down ;; deploy) deploy_down ;;
            all) deploy_down; monitor_down; db_down ;;
        esac ;;
    restart)
        case "$target" in
            db) db_down; db_up ;; monitor) monitor_down; monitor_up ;; deploy) deploy_down; deploy_up ;;
            all) deploy_down; monitor_down; db_up && monitor_up && deploy_up ;;
        esac ;;
    status) status ;;
    rotate-logs) rotate_logs ;;
    reset-db)
        monitor_down
        (cd "$DIR" && ./stop_postgres.sh >/dev/null 2>&1)
        db_up ;;
    *) echo "usage: $0 {up|down|restart|status|rotate-logs|reset-db} [db|monitor|deploy|all]" >&2; exit 2 ;;
esac
