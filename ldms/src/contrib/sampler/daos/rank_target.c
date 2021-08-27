/* -*- c-basic-offset: 8 -*- */
/**
 * (C) Copyright 2021 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#include <coll/rbt.h>
#include "ldms.h"
#include "ldmsd.h"

#include <gurt/telemetry_common.h>
#include <gurt/telemetry_consumer.h>
#include <daos_types.h>
#include "daos.h"

#define INSTANCE_NAME_BUF_LEN (DAOS_SYS_NAME_MAX + 17)

static ldms_schema_t rank_target_schema;

static struct rbt rank_targets;

static char *rank_target_lat_metrics[] = {
	"io/latency/update",
	"io/latency/fetch",
	NULL,
};

static char *rank_target_ops_metrics[] = {
	"io/ops/update",
	"io/ops/fetch",
	"io/ops/dkey_enum",
	"io/ops/akey_enum",
	"io/ops/recx_enum",
	"io/ops/obj_enum",
	"io/ops/obj_punch",
	"io/ops/dkey_punch",
	"io/ops/akey_punch",
	"io/ops/key_query",
	"io/ops/obj_sync",
	"io/ops/tgt_update",
	"io/ops/tgt_punch",
	"io/ops/tgt_dkey_punch",
	"io/ops/tgt_akey_punch",
	"io/ops/migrate",
	"io/ops/ec_agg",
	"io/ops/ec_rep",
	"io/ops/compound",
	NULL,
};

static char *rank_target_ops_keys[] = {
	"active",
	"latency",
	NULL,
};

static char *rank_target_lat_buckets[] = {
	"256B",
	"512B",
	"1KB",
	"2KB",
	"4KB",
	"8KB",
	"16KB",
	"32KB",
	"64KB",
	"128KB",
	"256KB",
	"512KB",
	"1MB",
	"2MB",
	"4MB",
	"GT4MB",
	NULL,
};

static char *u64_stat_names[] = {
	"min",
	"max",
	"samples",
	NULL,
};

static char *d64_stat_names[] = {
	"mean",
	"stddev",
	NULL,
};

struct rank_target_data {
	char		*system;
	uint32_t	 rank;
	uint32_t	 target;
	ldms_set_t	 metrics;
	struct rbn	 rank_targets_node;
};

int rank_target_schema_is_initialized(void)
{
	if (rank_target_schema != NULL)
		return 0;
	return -1;
}

void rank_target_schema_fini(void)
{
	log_fn(LDMSD_LDEBUG, SAMP": rank_target_schema_fini()\n");
	if (rank_target_schema != NULL) {
		ldms_schema_delete(rank_target_schema);
		rank_target_schema = NULL;
	}
}

int rank_target_schema_init(void)
{
	ldms_schema_t	sch;
	int		rc, i, j, k;
	char		name[64];

	log_fn(LDMSD_LDEBUG, SAMP": rank_target_schema_init()\n");
	sch = ldms_schema_new("daos_rank_target");
	if (sch == NULL)
		goto err1;
	rc = ldms_schema_meta_array_add(sch, "system", LDMS_V_CHAR_ARRAY,
					DAOS_SYS_NAME_MAX + 1);
	if (rc < 0)
		goto err2;
	rc = ldms_schema_meta_array_add(sch, "rank", LDMS_V_U32, 1);
	if (rc < 0)
		goto err2;
	rc = ldms_schema_meta_array_add(sch, "target", LDMS_V_U32, 1);
	if (rc < 0)
		goto err2;

	for (i = 0; rank_target_lat_metrics[i] != NULL; i++) {
		for (j = 0; rank_target_lat_buckets[j] != NULL; j++) {
			snprintf(name, sizeof(name), "%s/%s",
				rank_target_lat_metrics[i],
				rank_target_lat_buckets[j]);
			rc = ldms_schema_metric_add(sch, name, LDMS_V_U64);
			if (rc < 0)
				goto err2;

			for (k = 0; u64_stat_names[k] != NULL; k++) {
				snprintf(name, sizeof(name), "%s/%s/%s",
					rank_target_lat_metrics[i],
					rank_target_lat_buckets[j],
					u64_stat_names[k]);
				rc = ldms_schema_metric_add(sch, name, LDMS_V_U64);
				if (rc < 0)
					goto err2;
			}
			for (k = 0; d64_stat_names[k] != NULL; k++) {
				snprintf(name, sizeof(name), "%s/%s/%s",
					rank_target_lat_metrics[i],
					rank_target_lat_buckets[j],
					d64_stat_names[k]);
				rc = ldms_schema_metric_add(sch, name, LDMS_V_D64);
				if (rc < 0)
					goto err2;
			}
		}
	}

	for (i = 0; rank_target_ops_metrics[i] != NULL; i++) {
		for (j = 0; rank_target_ops_keys[j] != NULL; j++) {
			snprintf(name, sizeof(name), "%s/%s",
				rank_target_ops_metrics[i],
				rank_target_ops_keys[j]);
			rc = ldms_schema_metric_add(sch, name, LDMS_V_U64);
			if (rc < 0)
				goto err2;

			for (k = 0; u64_stat_names[k] != NULL; k++) {
				snprintf(name, sizeof(name), "%s/%s/%s",
					rank_target_ops_metrics[i],
					rank_target_ops_keys[j],
					u64_stat_names[k]);
				rc = ldms_schema_metric_add(sch, name, LDMS_V_U64);
				if (rc < 0)
					goto err2;
			}
			for (k = 0; d64_stat_names[k] != NULL; k++) {
				snprintf(name, sizeof(name), "%s/%s/%s",
					rank_target_ops_metrics[i],
					rank_target_ops_keys[j],
					d64_stat_names[k]);
				rc = ldms_schema_metric_add(sch, name, LDMS_V_D64);
				if (rc < 0)
					goto err2;
			}
		}
	}

	rank_target_schema = sch;
	return 0;

err2:
	ldms_schema_delete(sch);
err1:
	log_fn(LDMSD_LERROR, SAMP": daos_rank_target schema creation failed\n");
	return -1;
}

struct rank_target_data *rank_target_create(char *system, uint32_t rank,
					    uint32_t target,
					    const char *instance_name)
{
	struct rank_target_data	*rtd = NULL;
	char			*key = NULL;
	ldms_set_t		 set;
	int			 index;

	rtd = calloc(1, sizeof(*rtd));
	if (rtd == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	rtd->system = strndup(system, DAOS_SYS_NAME_MAX + 1);
	if (rtd->system == NULL) {
		errno = ENOMEM;
		goto err1;
	}
	rtd->rank = rank;
	rtd->target = target;

	key = strndup(instance_name, INSTANCE_NAME_BUF_LEN);
	if (key == NULL) {
		errno = ENOMEM;
		goto err2;
	}
	rbn_init(&rtd->rank_targets_node, key);

	set = ldms_set_new(instance_name, rank_target_schema);
	if (set == NULL)
		goto err3;
	index = ldms_metric_by_name(set, "system");
	ldms_metric_array_set_str(set, index, system);
	index = ldms_metric_by_name(set, "rank");
	ldms_metric_set_u32(set, index, rank);
	index = ldms_metric_by_name(set, "target");
	ldms_metric_set_u32(set, index, target);
	ldms_set_publish(set);

	rtd->metrics = set;
	return rtd;

err3:
	free(key);
err2:
	free(rtd->system);
err1:
	free(rtd);
	return NULL;
}

static void get_system_rank_targets(struct d_tm_context *ctx, char **system,
				    uint32_t *rank, uint32_t *ntarget)
{
	uint64_t		 ctr_rank = -1;
	struct d_tm_node_t	*node;

	if (system == NULL || rank == NULL || ntarget == NULL)
		return;

	// TODO: Get all of this info from segment metadata.
	*system = strdup("daos_server");

	node = d_tm_find_metric(ctx, "/rank");
	if (node != NULL)
		d_tm_get_counter(ctx, &ctr_rank, node);
	*rank = ctr_rank;

	*ntarget = 8;
	/*node = d_tm_find_metric(ctx, "num_targets");
	if (node != NULL) {
		d_tm_get_gauge(ctx, ntarget, NULL, node);
	}
	*/
}

static void rank_target_destroy(struct rank_target_data *rtd)
{
	if (rtd == NULL)
		return;

	if (rtd->metrics != NULL) {
		ldms_set_unpublish(rtd->metrics);
		ldms_set_delete(rtd->metrics);
	}

	free(rtd->system);
	free(rtd->rank_targets_node.key);
	free(rtd);
}

void rank_targets_destroy(void)
{
	struct rbn *rbn;
	struct rank_target_data *rtd;

	if (rbt_card(&rank_targets) > 0)
		log_fn(LDMSD_LDEBUG, SAMP": destroying %lu rank targets\n",
				     rbt_card(&rank_targets));

	while (!rbt_empty(&rank_targets)) {
		rbn = rbt_min(&rank_targets);
		rtd = container_of(rbn, struct rank_target_data,
					rank_targets_node);
		rbt_del(&rank_targets, rbn);
		rank_target_destroy(rtd);
	}
}

void rank_targets_refresh(int num_engines)
{
	int			 i;
	struct rbt		 new_rank_targets;
	int			 target;
	char			 instance_name[INSTANCE_NAME_BUF_LEN];

	rbt_init(&new_rank_targets, string_comparator);

	for (i = 0; i < num_engines; i++) {
		char		    *system = NULL;
		struct d_tm_context *ctx = NULL;
		uint32_t	     rank = -1;
		int		     ntarget = 0;

		ctx = d_tm_open(i);
		if (!ctx) {
			log_fn(LDMSD_LERROR, SAMP": Failed to open tm shm %d\n", i);
			continue;
		}

		get_system_rank_targets(ctx, &system, &rank, &ntarget);

		for (target = 0; target < ntarget; target++) {
			struct rbn *rbn = NULL;
			struct rank_target_data *rtd = NULL;

			snprintf(instance_name, sizeof(instance_name),
				 "%s/%d/%d", system, rank, target);

			rbn = rbt_find(&rank_targets, instance_name);
			if (rbn) {
				rtd = container_of(rbn, struct rank_target_data,
							rank_targets_node);
				rbt_del(&rank_targets, &rtd->rank_targets_node);
				//log_fn(LDMSD_LDEBUG, SAMP": found %s\n", instance_name);
			} else {
				rtd = rank_target_create(system, rank, target, instance_name);
				if (rtd == NULL) {
					log_fn(LDMSD_LERROR, SAMP": failed to create rank target %s (%s)\n",
								instance_name, strerror(errno));
					continue;
				}
				//log_fn(LDMSD_LDEBUG, SAMP": created %s\n", instance_name);
			}
			if (rtd == NULL)
				continue;

			rbt_ins(&new_rank_targets, &rtd->rank_targets_node);
		}

		free(system);
		d_tm_close(&ctx);
	}

	if (!rbt_empty(&new_rank_targets)) {
		rank_targets_destroy();
		memcpy(&rank_targets, &new_rank_targets, sizeof(struct rbt));
	}
}

static void rank_target_sample(struct d_tm_context *ctx,
			       uint32_t target, ldms_set_t set)
{
	struct d_tm_node_t	*node;
	struct d_tm_stats_t	 stats;
	char			 dtm_name[64];
	char			 ldms_name[64];
	const char		*stat_name;
	uint64_t		 cur;
	int			 rc;
	int			 index;
	int			 i, j, k;

	ldms_transaction_begin(set);
	for (i = 0; rank_target_lat_metrics[i] != NULL; i++) {
		for (j = 0; rank_target_lat_buckets[j] != NULL; j++) {
			stats = (const struct d_tm_stats_t) {0};

			snprintf(dtm_name, sizeof(dtm_name), "%s/%s/tgt_%d",
				rank_target_lat_metrics[i],
				rank_target_lat_buckets[j],
				target);
			node = d_tm_find_metric(ctx, dtm_name);
			if (node == NULL)
				continue;
			rc = d_tm_get_gauge(ctx, &cur, &stats, node);
			if (rc != DER_SUCCESS)
				continue;

			snprintf(ldms_name, sizeof(ldms_name), "%s/%s",
				rank_target_lat_metrics[i],
				rank_target_lat_buckets[j]);
			index = ldms_metric_by_name(set, ldms_name);
			if (index < 0)
				continue;
			ldms_metric_set_u64(set, index, cur);

			for (k = 0; u64_stat_names[k] != NULL; k++) {
				stat_name = u64_stat_names[k];
				snprintf(ldms_name, sizeof(ldms_name), "%s/%s/%s",
					rank_target_lat_metrics[i],
					rank_target_lat_buckets[j],
					stat_name);
				index = ldms_metric_by_name(set, ldms_name);
				if (index < 0)
					continue;

				if (strcmp(stat_name, "min") == 0)
					ldms_metric_set_u64(set, index, stats.dtm_min);
				else if (strcmp(stat_name, "max") == 0)
					ldms_metric_set_u64(set, index, stats.dtm_max);
				else if (strcmp(stat_name, "samples") == 0)
					ldms_metric_set_u64(set, index, stats.sample_size);
			}
			for (k = 0; d64_stat_names[k] != NULL; k++) {
				stat_name = d64_stat_names[k];
				snprintf(ldms_name, sizeof(ldms_name), "%s/%s/%s",
					rank_target_lat_metrics[i],
					rank_target_lat_buckets[j],
					stat_name);

				index = ldms_metric_by_name(set, ldms_name);
				if (index < 0)
					continue;

				if (strcmp(stat_name, "mean") == 0)
					ldms_metric_set_double(set, index, stats.mean);
				else if (strcmp(stat_name, "stddev") == 0)
					ldms_metric_set_double(set, index, stats.std_dev);
			}
		}
	}
	ldms_transaction_end(set);
}

void rank_targets_sample(struct d_tm_context *ctx)
{
	struct rbn *rbn;

	RBT_FOREACH(rbn, &rank_targets) {
		struct rank_target_data *rtd;

		rtd = container_of(rbn, struct rank_target_data,
					rank_targets_node);
		rank_target_sample(ctx, rtd->target, rtd->metrics);
	}
}