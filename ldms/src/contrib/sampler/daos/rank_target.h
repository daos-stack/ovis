/* -*- c-basic-offset: 8 -*- */
/**
 * (C) Copyright 2021 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#include <gurt/telemetry_common.h>

int rank_target_schema_is_initialized(void);
int rank_target_schema_init(void);
void rank_target_schema_fini(void);

void rank_targets_refresh(const char *system, int num_engines, int num_targets);
void rank_targets_sample(struct d_tm_context *ctx, uint32_t rank);
void rank_targets_destroy(void);
