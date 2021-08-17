/* -*- c-basic-offset: 8 -*- */
/**
 * (C) Copyright 2021 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#include <gurt/telemetry_common.h>

int pool_target_schema_is_initialized(void);
int pool_target_schema_init(void);
void pool_target_schema_fini(void);

void pool_targets_refresh(const char *system, int num_engines, int num_targets);
void pool_targets_sample(struct d_tm_context *ctx, uint32_t rank);
void pool_targets_destroy(void);
