#!/usr/bin/env bash
# Campaign run entirely on the server (orchestrator and services on the same machine).
#
#   run_campaign_server.sh <raw_dir> [nodes] [iterations] [fault_repetitions] [results_dir]
#
# Scenarios, for each iteration: standard loop (bootstrap/join with election, authentication of SRAFT,
# removal with healing, then the baselines on devices started without SRAFT: TLS with a full handshake, TLS
# with session resumption, and MQTTS) and attestation; then, for each repetition, the four fault
# scenarios (crash of 2 devices with and without the Coordinator, alteration of a running device with and
# without the Coordinator). Every run is a separate invocation, preceded by a restart of the services and
# a rotation of the serial logs, so that each iteration has its own logs.
#
# <raw_dir> receives the raw output of the runs, logs included. If <results_dir> is given, the runs are then
# added to <results_dir>/output with the layout of the archived experimental_results/ folder, without logs (aggregate_campaign.py),
# and the statistics and plots of everything in <results_dir>/output are regenerated. Several network sizes can be added to the same
# <results_dir> by running the script once per size.
set -u
OUT=$(realpath -m "${1:?raw_dir}")
NODES=${2:-7}
ITER=${3:-1}
FAULT_REPS=${4:-1}
RESULTS=${5:+$(realpath -m "$5")}

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_DIR="$(cd "$TESTS_DIR/../server" && pwd)"
PY="$SERVER_DIR/venv/bin/python"
export SRAFT_LOCAL_DEPLOY=1
export SRAFT_BUILD_DIR=build_release
export SRAFT_TAMPERED_BUILD_DIR=build_release_tampered
mkdir -p "$OUT"
log() { echo "[$(date '+%F %T')] $*" | tee -a "$OUT/driver.log"; }

restart_services() {
    (cd "$SERVER_DIR" && ./services.sh down deploy && ./services.sh down monitor && \
     ./services.sh rotate-logs && ./services.sh up all) >> "$OUT/services.log" 2>&1
}

save_logs() {
    mkdir -p "$1/serial_logs" "$1/server_output"
    cp "$SERVER_DIR"/logs/*.log "$1/serial_logs/" 2>/dev/null
    cp "$SERVER_DIR"/run/*.out "$1/server_output/" 2>/dev/null
}

run_scenario() {
    local name=$1; shift
    log "$name start: $*"
    restart_services
    (cd "$TESTS_DIR" && "$PY" -u experimental_campaign.py -n "$NODES" "$@") > "$OUT/$name.log" 2>&1
    local rc=$?
    save_logs "$OUT/logs_$name"
    log "$name end (exit $rc)"
}

log "campaign: $NODES devices, $ITER iteration(s), $FAULT_REPS fault repetition(s)${RESULTS:+, results in $RESULTS}"
for it in $(seq 1 "$ITER"); do
    run_scenario "standard_i$it" --loop -i 1 --out "$OUT/standard" --tag "srv_i$it"
    run_scenario "attestation_i$it" --attestation-test -i 1 --out "$OUT" --tag "srv_i$it"
done
for rep in $(seq 1 "$FAULT_REPS"); do
    run_scenario "fault_crash2_r$rep" --fault crash --fault-count 2 --out "$OUT/faults" --tag "srv_r$rep"
    run_scenario "fault_crash2coord_r$rep" --fault crash --fault-count 2 --fault-coordinator --out "$OUT/faults" --tag "srv_r$rep"
    run_scenario "fault_tamper1_r$rep" --fault tamper --fault-count 1 --out "$OUT/faults" --tag "srv_r$rep"
    run_scenario "fault_tamper1coord_r$rep" --fault tamper --fault-count 1 --fault-coordinator --out "$OUT/faults" --tag "srv_r$rep"
done
(cd "$SERVER_DIR" && ./services.sh down deploy) >> "$OUT/services.log" 2>&1

if [ -n "$RESULTS" ]; then
    log "aggregation into $RESULTS/output"
    "$PY" "$TESTS_DIR/aggregate_campaign.py" "$RESULTS/output" "$OUT" --analyze >> "$OUT/driver.log" 2>&1
    log "aggregation end (exit $?)"
fi
log "campaign complete"
