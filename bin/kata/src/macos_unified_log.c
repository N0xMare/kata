#include <os/log.h>
#include <stdint.h>

// Rust passes a compact private enum rather than depending on Apple's numeric
// os_log_type_t representation. Keep policy here at the only C boundary:
// trace/debug are ephemeral debug records, info is the normal persistent
// service stream, and warn/error are persistent error records. Kata errors are
// process-level failures, not OS_LOG_TYPE_FAULT system-wide faults.
static os_log_type_t kata_os_log_type(uint8_t level) {
    switch (level) {
    case 0:
        return OS_LOG_TYPE_DEBUG;
    case 1:
        return OS_LOG_TYPE_DEFAULT;
    case 2:
        return OS_LOG_TYPE_ERROR;
    default:
        return OS_LOG_TYPE_ERROR;
    }
}

void *kata_os_log_create(const char *subsystem, const char *category) {
    return (void *)os_log_create(subsystem, category);
}

void kata_os_log_write(void *raw_log, uint8_t level, const char *message) {
    os_log_with_type((os_log_t)raw_log, kata_os_log_type(level),
                     "%{public}s", message);
}

void kata_os_log_release(void *raw_log) {
    os_release((os_log_t)raw_log);
}
