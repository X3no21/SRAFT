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

static const char *TAG = "STATS_SAMPLER";

static stats_sample_t stats_buffer[STATS_BUFFER_SIZE];
static volatile uint32_t buffer_head = 0;
static SemaphoreHandle_t buffer_mutex;

static uint32_t checkpoint_stack[CHECKPOINT_STACK_SIZE];
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
 * @brief A FreeRTOS task that periodically samples system statistics.
 * @param pvParameters Unused task parameters.
 */
static void stats_sampler_task(void *pvParameters) {
    ESP_LOGI(TAG, "Statistics sampling task started. Interval: %d ms.", SAMPLING_INTERVAL_MS);
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(SAMPLING_INTERVAL_MS));

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

        xSemaphoreTake(buffer_mutex, portMAX_DELAY);
        stats_buffer[buffer_head] = sample;
        buffer_head = (buffer_head + 1) % STATS_BUFFER_SIZE;
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
    
    checkpoint_stack_top++;
    checkpoint_stack[checkpoint_stack_top] = buffer_head;
    
    ESP_LOGI(TAG, "Phase started. Checkpoint created at index %lu, stack depth: %d", buffer_head, checkpoint_stack_top + 1);

    xSemaphoreGive(buffer_mutex);
    return ESP_OK;
}

/**
 * @brief Calculates aggregate statistics from the collected samples and clears the buffer.
 */
esp_err_t stats_sampler_end_phase_and_get_aggregates(aggregate_stats_t *results) {
    memset(results, 0, sizeof(aggregate_stats_t));
    xSemaphoreTake(buffer_mutex, portMAX_DELAY);

    if (checkpoint_stack_top < 0) {
        ESP_LOGE(TAG, "Checkpoint stack underflow! No phase to end.");
        xSemaphoreGive(buffer_mutex);
        return ESP_FAIL;
    }

    uint32_t start_index = checkpoint_stack[checkpoint_stack_top];
    checkpoint_stack_top--;
    
    uint32_t end_index = buffer_head;
    int sample_count = (end_index - start_index + STATS_BUFFER_SIZE) % STATS_BUFFER_SIZE;
    
    ESP_LOGI(TAG, "Phase ended. Calculating stats from index %lu to %lu (%d samples). Stack depth: %d", start_index, end_index, sample_count, checkpoint_stack_top + 1);

    if (sample_count < 2) {
        xSemaphoreGive(buffer_mutex);
        results->sample_count = sample_count;
        return ESP_FAIL;
    }

    stats_sample_t *local_samples = malloc(sample_count * sizeof(stats_sample_t));
    if (local_samples == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for local samples buffer!");
        checkpoint_stack_top++;
        xSemaphoreGive(buffer_mutex);
        return ESP_FAIL;
    }

    for (int i = 0; i < sample_count; i++) {
        local_samples[i] = stats_buffer[(start_index + i) % STATS_BUFFER_SIZE];
    }
    
    xSemaphoreGive(buffer_mutex);

    results->sample_count = sample_count;
    double sum_cpu = 0, sum_mem = 0, sum_pow = 0;
    double auc_cpu = 0, auc_mem = 0, auc_pow = 0;

    for (int i = 0; i < sample_count; i++) {
        sum_cpu += local_samples[i].cpu_usage_percent;
        sum_mem += local_samples[i].memory_load_percent;
        sum_pow += local_samples[i].estimated_power_mw;
    }
    
    for (int i = 0; i < sample_count - 1; i++) {
        double delta_t_s = (local_samples[i+1].timestamp_ms - local_samples[i].timestamp_ms) / 1000.0;
        if (delta_t_s < 0) continue;
        
        auc_cpu += (local_samples[i].cpu_usage_percent + local_samples[i+1].cpu_usage_percent) / 2.0 * delta_t_s;
        auc_mem += (local_samples[i].memory_load_percent + local_samples[i+1].memory_load_percent) / 2.0 * delta_t_s;
        auc_pow += (local_samples[i].estimated_power_mw + local_samples[i+1].estimated_power_mw) / 2.0 * delta_t_s;
    }

    results->avg_cpu = sum_cpu / sample_count;
    results->avg_memory = sum_mem / sample_count;
    results->avg_power = sum_pow / sample_count;
    
    results->auc_cpu = auc_cpu;
    results->auc_memory = auc_mem;
    results->auc_power = auc_pow;
    
    free(local_samples);
    
    return ESP_OK;
}