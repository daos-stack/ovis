/* -*- c-basic-offset: 8 -*- */
/**
 * (C) Copyright 2021 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#include <string.h>

#define SAMP "daos"

extern ldmsd_msg_log_f log_fn;

static int string_comparator(void *a, const void *b)
{
	return strcmp((char *)a, (char *)b);
}