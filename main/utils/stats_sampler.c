/* =============================
 * File: stats_sampler.c
 * Description: Implementation of the background statistics sampling module.
 * ============================= */

#include "stats_sampler.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/portmacro.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include <string.h>

static const char *TAG = "STATS_SAMPLER";

static SemaphoreHandle_t buffer_mutex;

/**
 * @brief Running aggregates of an open phase. Every sample taken while the phase is open is added to
 * them, so that a phase of any length is measured over all its samples (a circular buffer of samples
 * would lose the beginning of the phases longer than the buffer).
 */
typedef struct {
    int count;
    double sum_cpu, sum_mem, sum_pow;
    double auc_cpu, auc_mem, auc_pow;
    stats_sample_t last;   // last sample added, for the area under the curve
} phase_acc_t;

static phase_acc_t checkpoint_stack[CHECKPOINT_STACK_SIZE];
static volatile int checkpoint_stack_top = -1;

static portMUX_TYPE stats_sampler_init_spinlock = portMUX_INITIALIZER_UNLOCKED;

/**
 * @brief Samples the CPU usage of a specific core since the last call.
 * @details This function calculates CPU usage by measuring the time the idle task has spent
 * running over a time interval. It is stateful and must be called periodically.
 * @param core_id The core to measure (0 or 1).
 * @return The calculated CPU usage percentage as a float.
 */
static float sample_cpu_usage(int core_id) {
    TaskStatus_t idle_task_status;
    TaskHandle_t idle_handle = xTaskGetIdleTaskHandleForCore(core_id);
    if (!idle_handle) return 0.0f;

    static uint32_t prev_idle_time[2] = {0, 0};
    static uint64_t prev_time_us[2] = {0, 0};

    vTaskGetInfo(idle_handle, &idle_task_status, pdTRUE, eInvalid);
    uint32_t current_idle_time = idle_task_status.ulRunTimeCounter;
    uint64_t current_time_us = esp_timer_get_time();

    if (prev_time_us[core_id] == 0) {
        prev_idle_time[core_id] = current_idle_time;
        prev_time_us[core_id] = current_time_us;
        return 0.0f;
    }

    uint32_t idle_time_diff = current_idle_time - prev_idle_time[core_id];
    uint64_t total_time_diff = current_time_us - prev_time_us[core_id];

    prev_idle_time[core_id] = current_idle_time;
    prev_time_us[core_id] = current_time_us;

    if (total_time_diff == 0) return 0.0f;

    float idle_percentage = ((float)idle_time_diff / total_time_diff) * 100.0f;
    float cpu_usage = 100.0f - idle_percentage;

    return (cpu_usage >= 0.0f) ? cpu_usage : 0.0f;
}

/**
 * @brief Takes a sample. Must be called with buffer_mutex held, which also serializes the stateful
 * CPU measurement of sample_cpu_usage().
 * @details The CPU load of a sample is the one since the previous sample, whichever task took it.
 */
static stats_sample_t take_sample_locked(void) {
    stats_sample_t sample;
    sample.timestamp_ms = esp_timer_get_time() / 1000;

    size_t total_heap = heap_caps_get_total_size(MALLOC_CAP_INTERNAL);
    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    sample.memory_load_percent = (total_heap > 0) ? (100.0f * (total_heap - free_heap) / total_heap) : 0;

    sample.cpu_usage_percent = sample_cpu_usage(0);

    const float IDLE_CURRENT_MA = 44.0f;
    const float MAX_CURRENT_MA = 239.0f;
    float estimated_current_ma = IDLE_CURRENT_MA + ((MAX_CURRENT_MA - IDLE_CURRENT_MA) * (sample.cpu_usage_percent / 100.0f));
    sample.estimated_power_mw = estimated_current_ma * ESP32_VOLTAGE_V;
    return sample;
}

/**
 * @brief Adds a sample to every open phase. Must be called with buffer_mutex held.
 */
static void add_sample_locked(const stats_sample_t *s) {
    for (int i = 0; i <= checkpoint_stack_top; i++) {
        phase_acc_t *p = &checkpoint_stack[i];
        if (p->count > 0) {
            double dt = (s->timestamp_ms - p->last.timestamp_ms) / 1000.0;
            if (dt > 0) {
                p->auc_cpu += (p->last.cpu_usage_percent + s->cpu_usage_percent) / 2.0 * dt;
                p->auc_mem += (p->last.memory_load_percent + s->memory_load_percent) / 2.0 * dt;
                p->auc_pow += (p->last.estimated_power_mw + s->estimated_power_mw) / 2.0 * dt;
            }
        }
        p->sum_cpu += s->cpu_usage_percent;
        p->sum_mem += s->memory_load_percent;
        p->sum_pow += s->estimated_power_mw;
        p->last = *s;
        p->count++;
    }
}

/**
 * @brief A FreeRTOS task that periodically samples system statistics.
 * @param pvParameters Unused task parameters.
 */
static void stats_sampler_task(void *pvParameters) {
    ESP_LOGI(TAG, "Statistics sampling task started. Interval: %d ms.", SAMPLING_INTERVAL_MS);
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(SAMPLING_INTERVAL_MS));
        xSemaphoreTake(buffer_mutex, portMAX_DELAY);
        stats_sample_t sample = take_sample_locked();
        add_sample_locked(&sample);
        xSemaphoreGive(buffer_mutex);
    }
}

/**
 * @brief Initializes and starts the background statistics sampling task.
 */
void stats_sampler_init(void) {
    taskENTER_CRITICAL(&stats_sampler_init_spinlock);
    if (buffer_mutex == NULL) {
        buffer_mutex = xSemaphoreCreateMutex();
    }
    taskEXIT_CRITICAL(&stats_sampler_init_spinlock);

     if (buffer_mutex == NULL) {
        ESP_LOGE(TAG, "FATAL: Failed to create BUFFER mutex!");
        return;
    }

    ESP_LOGD(TAG, "Attempting to take BUFFER mutex for initialization...");
    if (xSemaphoreTake(buffer_mutex, portMAX_DELAY) != pdTRUE) {
        ESP_LOGE(TAG, "FATAL: Failed to create BUFFER mutex!");
        return;
    } else {
        xSemaphoreGive(buffer_mutex);
    }

    xTaskCreate(stats_sampler_task, "stats_sampler", 4096, NULL, 5, NULL);
}

esp_err_t stats_sampler_start_phase(void) {
    xSemaphoreTake(buffer_mutex, portMAX_DELAY);

    if (checkpoint_stack_top >= (CHECKPOINT_STACK_SIZE - 1)) {
        ESP_LOGE(TAG, "Checkpoint stack overflow! Cannot start new phase.");
        xSemaphoreGive(buffer_mutex);
        return ESP_FAIL;
    }

    // A sample taken now closes the interval before the phase: it goes to the phases already open, not
    // to the new one, whose first sample (periodic or taken at its end) measures the CPU load from now.
    stats_sample_t sample = take_sample_locked();
    add_sample_locked(&sample);

    checkpoint_stack_top++;
    memset(&checkpoint_stack[checkpoint_stack_top], 0, sizeof(phase_acc_t));

    ESP_LOGI(TAG, "Phase started. Stack depth: %d", checkpoint_stack_top + 1);

    xSemaphoreGive(buffer_mutex);
    return ESP_OK;
}

/**
 * @brief Calculates aggregate statistics of the most recently started phase and ends it.
 */
esp_err_t stats_sampler_end_phase_and_get_aggregates(aggregate_stats_t *results) {
    memset(results, 0, sizeof(aggregate_stats_t));
    xSemaphoreTake(buffer_mutex, portMAX_DELAY);

    if (checkpoint_stack_top < 0) {
        ESP_LOGE(TAG, "Checkpoint stack underflow! No phase to end.");
        xSemaphoreGive(buffer_mutex);
        return ESP_FAIL;
    }

    // A sample taken now covers the end of the phase, so that a phase shorter than the sampling interval
    // still has one sample, which measures exactly its duration.
    stats_sample_t sample = take_sample_locked();
    add_sample_locked(&sample);

    phase_acc_t p = checkpoint_stack[checkpoint_stack_top];
    checkpoint_stack_top--;
    xSemaphoreGive(buffer_mutex);

    ESP_LOGI(TAG, "Phase ended with %d samples. Stack depth: %d", p.count, checkpoint_stack_top + 1);
    results->sample_count = p.count;
    if (p.count < 1) {
        return ESP_FAIL;
    }

    results->avg_cpu = p.sum_cpu / p.count;
    results->avg_memory = p.sum_mem / p.count;
    results->avg_power = p.sum_pow / p.count;
    results->auc_cpu = p.auc_cpu;
    results->auc_memory = p.auc_mem;
    results->auc_power = p.auc_pow;
    return ESP_OK;
}
