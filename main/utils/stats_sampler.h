/* =============================
 * File: stats_sampler.h
 * Description: Public interface for the background statistics sampling module.
 * ============================= */
#ifndef STATS_SAMPLER_H
#define STATS_SAMPLER_H

#include "esp_err.h"

#define SAMPLING_INTERVAL_MS 100
#define CHECKPOINT_STACK_SIZE 32
#define ESP32_VOLTAGE_V 3.3f

/**
 * @struct stats_sample_t
 * @brief Represents a single snapshot of system statistics at a specific time.
 */
typedef struct {
    uint64_t timestamp_ms;
    float cpu_usage_percent;
    float memory_load_percent;
    float estimated_power_mw;
} stats_sample_t;

/**
 * @struct aggregate_stats_t
 * @brief Holds the aggregated results (average and AUC) calculated from a series of samples.
 */
typedef struct {
    float avg_cpu;
    double auc_cpu;
    float avg_memory;
    double auc_memory;
    float avg_power;
    double auc_power;
    int sample_count;
} aggregate_stats_t;

/**
 * @brief Initializes and starts the background statistics sampling task.
 */
void stats_sampler_init(void);

/**
 * @brief Marks the beginning of a new measurement phase by pushing a checkpoint.
 * @details This function should be called at the start of any operation (e.g., JOIN_START,
 * REMOVE_START) for which statistics need to be measured. It opens a phase on a stack; every
 * sample taken until the phase ends is added to its aggregates.
 * @return ESP_OK on success, ESP_FAIL if the checkpoint stack is full.
 */
esp_err_t stats_sampler_start_phase(void);

/**
 * @brief Calculates aggregate statistics for the most recently started phase and ends it.
 * @details This function takes a last sample, returns the aggregates of all the samples of the phase,
 * and pops it from the stack, returning to the context of any outer (parent) phase.
 *
 * @param[out] results A pointer to an aggregate_stats_t struct where the calculated results will be stored.
 * @return
 * - ESP_OK if the calculation was successful.
 * - ESP_FAIL if the checkpoint stack was empty.
 */
esp_err_t stats_sampler_end_phase_and_get_aggregates(aggregate_stats_t *results);

#endif // STATS_SAMPLER_H