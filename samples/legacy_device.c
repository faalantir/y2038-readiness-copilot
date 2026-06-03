#include <stdint.h>
#include <time.h>
#include <stdio.h>

typedef struct {
    int32_t device_id;
    int32_t boot_time;              // suspicious: time-like data in signed 32-bit field
    uint32_t last_seen_epoch;       // unsigned, still protocol/interoperability context
    time_t certificate_expiry_time; // platform context needed
} DeviceStatus;

int32_t get_certificate_expiry(void) {
    time_t certificate_expiry = time(NULL) + (20L * 365L * 24L * 60L * 60L);
    return (int32_t) certificate_expiry; // explicit narrowing cast
}

void write_state(FILE *fp, DeviceStatus *status) {
    fwrite(&status->certificate_expiry_time, sizeof(time_t), 1, fp); // binary-format risk if time_t width changes
}

int main(void) {
    int event_time = time(NULL); // assignment from time_t to int
    printf("event_time=%d\n", event_time);
    return 0;
}
