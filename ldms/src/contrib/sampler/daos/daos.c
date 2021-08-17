/* -*- c-basic-offset: 8 -*- */
/**
 * (C) Copyright 2021 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#include "ldms.h"
#include "ldmsd.h"
#include "config.h"
#include "sampler_base.h"

#include "gurt/telemetry_common.h"
#include "gurt/telemetry_consumer.h"
#include "daos_types.h"
#include "daos.h"

#include "rank_target.h"
#include "pool_target.h"

ldmsd_msg_log_f log_fn;
static ldmsd_msg_log_f msglog;
static int engine_count = 2;
static int target_count = 8;
char system_name[DAOS_SYS_NAME_MAX+1];
char producer_name[LDMS_PRODUCER_NAME_MAX];

#define DEFAULT_SYS_NAME "daos_server"

static int
config(struct ldmsd_plugin *self,
		  struct attr_value_list *kwl, struct attr_value_list *avl)
{
	char	*ival;

	log_fn(LDMSD_LDEBUG, SAMP": config() called\n");
	ival = av_value(avl, "producer");
	if (ival) {
		if (strlen(ival) < sizeof(producer_name)) {
			strncpy(producer_name, ival, sizeof(producer_name));
		} else {
			log_fn(LDMSD_LERROR, SAMP": config: producer name too long.\n");
			return -EINVAL;
		}
	}
	log_fn(LDMSD_LDEBUG, SAMP": producer: %s\n", producer_name);

	ival = av_value(avl, "system");
	if (ival) {
		if (strlen(ival) < sizeof(system_name)) {
			strncpy(system_name, ival, sizeof(system_name));
		} else {
			log_fn(LDMSD_LERROR, SAMP": config: system name too long.\n");
			return -EINVAL;
		}
	}
	log_fn(LDMSD_LDEBUG, SAMP": system: %s\n", system_name);

	ival = av_value(avl, "engine_count");
	if (ival) {
		int cfg_engine_count = atoi(ival);
		if (cfg_engine_count > 0) {
			engine_count = cfg_engine_count;
		}
	}
	log_fn(LDMSD_LDEBUG, SAMP": engine_count: %d\n", engine_count);

	ival = av_value(avl, "target_count");
	if (ival) {
		int cfg_tgt_count = atoi(ival);
		if (cfg_tgt_count > 0) {
			target_count = cfg_tgt_count;
		}
	}
	log_fn(LDMSD_LDEBUG, SAMP": target_count: %d\n", target_count);


out:
	return 0;
}

int
get_daos_rank(struct d_tm_context *ctx, uint32_t *rank)
{
	uint64_t		 val;
	struct d_tm_node_t	*node;
	int			 rc;

	node = d_tm_find_metric(ctx, "/rank");
	if (node == NULL)
		return -EINVAL;

	rc = d_tm_get_gauge(ctx, &val, NULL, node);
	if (rc < 0) {
		log_fn(LDMSD_LERROR, SAMP": get_daos_rank: d_tm_get_gauge failed: %d\n", rc);
		return rc;
	}
	*rank = val;

	return 0;
}

static int
sample(struct ldmsd_sampler *self)
{
	struct d_tm_context	*ctx = NULL;
	uint32_t		 rank = -1;
	int			 i;
	int			 rc = 0;

	log_fn(LDMSD_LDEBUG, SAMP": sample() called\n");
	if (rank_target_schema_is_initialized() < 0) {
		if (rank_target_schema_init() < 0) {
			log_fn(LDMSD_LERROR, SAMP": rank_target_schema_init failed.\n");
			return ENOMEM;
		}
	}
	if (pool_target_schema_is_initialized() < 0) {
		if (pool_target_schema_init() < 0) {
			log_fn(LDMSD_LERROR, SAMP": pool_target_schema_init failed.\n");
			return ENOMEM;
		}
	}

	rank_targets_refresh(system_name, engine_count, target_count);
	pool_targets_refresh(system_name, engine_count, target_count);

	for (i = 0; i < engine_count; i++) {
		ctx = d_tm_open(i);
		if (!ctx) {
			log_fn(LDMSD_LERROR, SAMP": Failed to open tm shm %d\n", i);
			continue;
		}

		rc = get_daos_rank(ctx, &rank);
		if (rc != 0) {
			log_fn(LDMSD_LERROR, SAMP": Failed to get rank from tm shm %d: %d\n", i, rc);
			continue;
		}

		rank_targets_sample(ctx, rank);
		pool_targets_sample(ctx, rank);

		d_tm_close(&ctx);
	}

	return rc;
}

static void
term(struct ldmsd_plugin *self)
{
	log_fn(LDMSD_LDEBUG, SAMP" term() called\n");
	rank_targets_destroy();
	rank_target_schema_fini();
	pool_targets_destroy();
	pool_target_schema_fini();
}

static ldms_set_t
get_set(struct ldmsd_sampler *self)
{
	return NULL;
}

static const char *
usage(struct ldmsd_plugin *self)
{
	log_fn(LDMSD_LDEBUG, SAMP" usage() called\n");
	return  "config name=" SAMP " " BASE_CONFIG_USAGE;
}

static struct ldmsd_sampler daos_plugin = {
	.base = {
		.name = SAMP,
		.type = LDMSD_PLUGIN_SAMPLER,
		.term = term,
		.config = config,
		.usage = usage,
	},
	.get_set = get_set,
	.sample = sample,
};

struct ldmsd_plugin *
get_plugin(ldmsd_msg_log_f pf)
{
	log_fn = pf;
	log_fn(LDMSD_LDEBUG, SAMP": get_plugin() called ("PACKAGE_STRING")\n");
	gethostname(producer_name, sizeof(producer_name));
	strncpy(system_name, DEFAULT_SYS_NAME, sizeof(system_name));

	return &daos_plugin.base;
}
