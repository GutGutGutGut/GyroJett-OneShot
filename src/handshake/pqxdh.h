#ifndef GYROJET_PQXDH_H
#define GYROJET_PQXDH_H

#include <stddef.h>

#define GYROJET_PQXDH_SHARED_SECRET_SIZE 32

typedef struct {
unsigned char shared_secret[
GYROJET_PQXDH_SHARED_SECRET_SIZE
];

unsigned char associated_data[64];

size_t associated_data_size;

} gyrojet_pqxdh_result_t;

int gyrojet_pqxdh_init(
void
);

int gyrojet_pqxdh_run_test(
gyrojet_pqxdh_result_t *result
);

void gyrojet_pqxdh_result_clear(
gyrojet_pqxdh_result_t *result
);

#endif

