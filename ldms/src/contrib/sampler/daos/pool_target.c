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
#include <daos_prop.h>
#include "daos.h"

#define INSTANCE_NAME_BUF_LEN (DAOS_SYS_NAME_MAX + \
			       DAOS_PROP_MAX_LABEL_BUF_LEN + 17)

static ldms_schema_t pool_target_schema;

static struct rbt pool_targets;

static char *pool_gauges[] = {
	"pool_handles",
	"container_handles",
	NULL,
};

static char *pool_counters[] = {
	"ops/cont_open",
	"ops/cont_close",
	"ops/cont_destroy",
	NULL,
};

static char *pool_target_counters[] = {
	"ops/dtx_commit",
	"ops/dtx_abort",
	"ops/dtx_check",
	"ops/dtx_refresh",
	"ops/update",
	"ops/fetch",
	"ops/dkey_enum",
	"ops/akey_enum",
	"ops/recx_enum",
	"ops/obj_enum",
	"ops/obj_punch",
	"ops/dkey_punch",
	"ops/akey_punch",
	"ops/key_query",
	"ops/obj_sync",
	"ops/tgt_update",
	"ops/tgt_punch",
	"ops/tgt_dkey_punch",
	"ops/tgt_akey_punch",
	"ops/migrate",
	"ops/ec_agg",
	"ops/ec_rep",
	"ops/compound",
	"restarted",
	"resent",
	"xferred/fetch",
	"xferred/update",
	NULL,
};

struct pool_target_data {
	char		*system;
	char		*pool;
	uint32_t	 rank;
	uint32_t	 target;
	ldms_set_t	 metrics;
	struct rbn	 pool_targets_node;
};

int pool_target_schema_is_initialized(void)
{
	if (pool_target_schema != NULL)
		return 0;
	return -1;
}

void pool_target_schema_fini(void)
{
	log_fn(LDMSD_LDEBUG, SAMP": pool_target_schema_fini()\n");
	if (pool_target_schema != NULL) {
		ldms_schema_delete(pool_target_schema);
		pool_target_schema = NULL;
	}
}

int pool_target_schema_init(void)
{
	ldms_schema_t	sch;
	int		rc, i;
	char		name[64];

	log_fn(LDMSD_LDEBUG, SAMP": pool_target_schema_init()\n");
	sch = ldms_schema_new("daos_pool_target");
	if (sch == NULL)
		goto err1;
	rc = ldms_schema_meta_array_add(sch, "system", LDMS_V_CHAR_ARRAY,
					DAOS_SYS_NAME_MAX + 1);
	if (rc < 0)
		goto err2;
	rc = ldms_schema_meta_array_add(sch, "rank", LDMS_V_U32, 1);
	if (rc < 0)
		goto err2;
	rc = ldms_schema_meta_array_add(sch, "pool", LDMS_V_CHAR_ARRAY,
					DAOS_PROP_MAX_LABEL_BUF_LEN);
	if (rc < 0)
		goto err2;
	rc = ldms_schema_meta_array_add(sch, "target", LDMS_V_U32, 1);
	if (rc < 0)
		goto err2;

	for (i = 0; pool_gauges[i] != NULL; i++) {
		snprintf(name, sizeof(name), "%s",
			pool_gauges[i]);
		rc = ldms_schema_metric_add(sch, name, LDMS_V_U64);
		if (rc < 0)
			goto err2;
	}

	for (i = 0; pool_counters[i] != NULL; i++) {
		snprintf(name, sizeof(name), "%s",
			pool_counters[i]);
		rc = ldms_schema_metric_add(sch, name, LDMS_V_U64);
		if (rc < 0)
			goto err2;
	}

	for (i = 0; pool_target_counters[i] != NULL; i++) {
		snprintf(name, sizeof(name), "%s",
			pool_target_counters[i]);
		rc = ldms_schema_metric_add(sch, name, LDMS_V_U64);
		if (rc < 0)
			goto err2;
	}

	pool_target_schema = sch;
	return 0;

err2:
	ldms_schema_delete(sch);
err1:
	log_fn(LDMSD_LERROR, SAMP": daos_pool_target schema creation failed\n");
	return -1;
}

struct pool_target_data *pool_target_create(char *system, uint32_t rank,
					    char *pool, uint32_t target,
					    const char *instance_name)
{
	char			*key = NULL;
	struct pool_target_data	*ptd = NULL;
	ldms_set_t		 set;
	int			 index;

	ptd = calloc(1, sizeof(*ptd));
	if (ptd == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	ptd->system = strndup(system, DAOS_SYS_NAME_MAX + 1);
	if (ptd->system == NULL) {
		errno = ENOMEM;
		goto err1;
	}
	ptd->pool = strndup(pool, DAOS_PROP_MAX_LABEL_BUF_LEN);
	if (ptd->pool == NULL) {
		errno = ENOMEM;
		goto err2;
	}
	ptd->rank = rank;
	ptd->target = target;

	key = strndup(instance_name, INSTANCE_NAME_BUF_LEN);
	if (key == NULL) {
		errno = ENOMEM;
		goto err3;
	}
	rbn_init(&ptd->pool_targets_node, key);

	set = ldms_set_new(instance_name, pool_target_schema);
	if (set == NULL)
		goto err4;
	index = ldms_metric_by_name(set, "system");
	ldms_metric_array_set_str(set, index, system);
	index = ldms_metric_by_name(set, "rank");
	ldms_metric_set_u32(set, index, rank);
	index = ldms_metric_by_name(set, "pool");
	ldms_metric_array_set_str(set, index, pool);
	index = ldms_metric_by_name(set, "target");
	ldms_metric_set_u32(set, index, target);
	ldms_set_publish(set);

	ptd->metrics = set;
	return ptd;

err4:
	free(key);
err3:
	free(ptd->pool);
err2:
	free(ptd->system);
err1:
	free(ptd);
	return NULL;
}

static void pool_list_free(char **pools, uint64_t npool)
{
	int i;

	if (pools == NULL)
		return;

	for (i = 0; i < npool; i++) {
		if (pools[i] != NULL)
			free(pools[i]);
	}
	free(pools);
}

static void get_system_pools_targets(struct d_tm_context *ctx, char **system,
				    uint32_t *rank, int *ntarget,
				    char ***pools, uint64_t *npool)
{
	uint64_t		 ctr_rank = -1;
	struct d_tm_nodeList_t	*list = NULL;
	struct d_tm_nodeList_t	*head = NULL;
	struct d_tm_node_t	*node = NULL;
	uint64_t		 num_pools = 0;
	char			**tmp_pools = NULL;
	int			 i, rc;

	if (system == NULL || rank == NULL || ntarget == NULL \
		|| pools == NULL || npool == NULL)
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

	node = d_tm_find_metric(ctx, "/pool");
	if (node == NULL)
		return;

	rc = d_tm_list_subdirs(ctx, &list, node, &num_pools, 2);
	if (rc != DER_SUCCESS)
		return;
	head = list;

	tmp_pools = calloc(num_pools, sizeof(char *));
	if (tmp_pools == NULL)
		return;

	for (i = 0; list && i < num_pools; i++) {
		char *name = NULL;

		node = list->dtnl_node;
		name = d_tm_get_name(ctx, node);
		if (name == NULL)
			goto err1;

		tmp_pools[i] = strndup(name, DAOS_PROP_MAX_LABEL_BUF_LEN);
		if (tmp_pools[i] == NULL)
			goto err1;

		list = list->dtnl_next;
	}
	d_tm_list_free(head);

	*pools = tmp_pools;
	*npool = num_pools;

	return;

err1:
	pool_list_free(tmp_pools, num_pools);
}

static void pool_target_destroy(struct pool_target_data *ptd)
{
	if (ptd == NULL)
		return;

	if (ptd->metrics != NULL) {
		ldms_set_unpublish(ptd->metrics);
		ldms_set_delete(ptd->metrics);
	}

	free(ptd->pool);
	free(ptd->system);
	free(ptd->pool_targets_node.key);
	free(ptd);
}

void pool_targets_destroy(void)
{
	struct rbn *rbn;
	struct pool_target_data *ptd;

	if (rbt_card(&pool_targets) > 0)
		log_fn(LDMSD_LDEBUG, SAMP": destroying %lu pool targets\n",
				     rbt_card(&pool_targets));

	while (!rbt_empty(&pool_targets)) {
		rbn = rbt_min(&pool_targets);
		ptd = container_of(rbn, struct pool_target_data,
					pool_targets_node);
		rbt_del(&pool_targets, rbn);
		pool_target_destroy(ptd);
	}
}

void pool_targets_refresh(int num_engines)
{
	int			 i;
	struct rbt		 new_pool_targets;
	int			 target;
	char			 instance_name[INSTANCE_NAME_BUF_LEN];

	rbt_init(&new_pool_targets, string_comparator);

	for (i = 0; i < num_engines; i++) {
		char		    *system = NULL;
		char		    **pools = NULL;
		uint64_t	     npools = 0;
		struct d_tm_context *ctx = NULL;
		uint32_t	     rank = -1;
		int		     ntarget = 0;
		int		     j;

		ctx = d_tm_open(i);
		if (!ctx) {
			log_fn(LDMSD_LERROR, SAMP": Failed to open tm shm %d\n", i);
			continue;
		}

		get_system_pools_targets(ctx, &system, &rank, &ntarget,
					 &pools, &npools);

		log_fn(LDMSD_LDEBUG, SAMP": rank %d, ntarget %d, npools %d\n",
					rank, ntarget, npools);
		/* iterate through all the pools */
		for (j = 0; j < npools; j++) {
			char *pool = pools[j];

			if (pool == NULL) {
				log_fn(LDMSD_LERROR, SAMP": rank %d, idx %d: pool is NULL\n",
							rank, j);
				continue;
			}

			for (target = 0; target < ntarget; target++) {
				struct rbn *rbn = NULL;
				struct pool_target_data *ptd = NULL;

				snprintf(instance_name, sizeof(instance_name),
					 "%s/%d/%s/%d", system, rank, pool, target);

				rbn = rbt_find(&pool_targets, instance_name);
				if (rbn) {
					ptd = container_of(rbn, struct pool_target_data,
							   pool_targets_node);
					rbt_del(&pool_targets, &ptd->pool_targets_node);
					//log_fn(LDMSD_LDEBUG, SAMP": found %s\n", ptd->pool_targets_node.key);
				} else {
					ptd = pool_target_create(system, rank, pool, target, instance_name);
					if (ptd == NULL) {
						log_fn(LDMSD_LERROR, SAMP": Failed to create pool target %s (%s)\n",
									instance_name, strerror(errno));
						continue;
					}
					//log_fn(LDMSD_LDEBUG, SAMP": created %s\n", ptd->pool_targets_node.key);
				}
				if (ptd == NULL)
					continue;

				rbt_ins(&new_pool_targets, &ptd->pool_targets_node);
			}
		}

		pool_list_free(pools, npools);
		free(system);
		d_tm_close(&ctx);
	}

	if (!rbt_empty(&new_pool_targets)) {
		pool_targets_destroy();
		memcpy(&pool_targets, &new_pool_targets, sizeof(struct rbt));
	}
}

static void pool_target_sample(struct d_tm_context *ctx, const char *pool,
			       uint32_t target, ldms_set_t set)
{
	struct d_tm_node_t	*node;
	char			 dtm_name[128];
	const char		*stat_name;
	uint64_t		 cur;
	int			 rc;
	int			 index;
	int			 i;

	ldms_transaction_begin(set);
	for (i = 0; pool_gauges[i] != NULL; i++) {
		snprintf(dtm_name, sizeof(dtm_name), "pool/%s/%s",
			 pool, pool_gauges[i]);
		node = d_tm_find_metric(ctx, dtm_name);
		if (node == NULL) {
			log_fn(LDMSD_LERROR,
			       SAMP": Failed to find metric %s\n", dtm_name);
			continue;
		}
		rc = d_tm_get_gauge(ctx, &cur, NULL, node);
		if (rc != DER_SUCCESS) {
			log_fn(LDMSD_LERROR,
			       SAMP": Failed to fetch gauge %s\n", dtm_name);
			continue;
		}

		index = ldms_metric_by_name(set, pool_gauges[i]);
		if (index < 0) {
			log_fn(LDMSD_LERROR,
			       SAMP": Failed to fetch index for %s\n", pool_gauges[i]);
			continue;
		}
		ldms_metric_set_u64(set, index, cur);
	}

	for (i = 0; pool_counters[i] != NULL; i++) {
		snprintf(dtm_name, sizeof(dtm_name), "pool/%s/%s",
			 pool, pool_counters[i]);
		node = d_tm_find_metric(ctx, dtm_name);
		if (node == NULL) {
			log_fn(LDMSD_LERROR,
			       SAMP": Failed to find metric %s\n", dtm_name);
			continue;
		}
		rc = d_tm_get_counter(ctx, &cur, node);
		if (rc != DER_SUCCESS) {
			log_fn(LDMSD_LERROR,
			       SAMP": Failed to fetch counter %s\n", dtm_name);
			continue;
		}

		index = ldms_metric_by_name(set, pool_counters[i]);
		if (index < 0) {
			log_fn(LDMSD_LERROR,
			       SAMP": Failed to fetch index for %s\n", pool_counters[i]);
			continue;
		}
		ldms_metric_set_u64(set, index, cur);
	}


	for (i = 0; pool_target_counters[i] != NULL; i++) {
		snprintf(dtm_name, sizeof(dtm_name), "pool/%s/%s/tgt_%d",
			 pool, pool_target_counters[i], target);
		node = d_tm_find_metric(ctx, dtm_name);
		if (node == NULL) {
			log_fn(LDMSD_LERROR,
			       SAMP": Failed to find metric %s\n", dtm_name);
			continue;
		}
		rc = d_tm_get_counter(ctx, &cur, node);
		if (rc != DER_SUCCESS) {
			log_fn(LDMSD_LERROR,
			       SAMP": Failed to fetch counter %s\n", dtm_name);
			continue;
		}

		index = ldms_metric_by_name(set, pool_target_counters[i]);
		if (index < 0) {
			log_fn(LDMSD_LERROR,
			       SAMP": Failed to fetch index for %s\n",
			       pool_target_counters[i]);
			continue;
		}
		ldms_metric_set_u64(set, index, cur);

	}
	ldms_transaction_end(set);
}

void pool_targets_sample(struct d_tm_context *ctx)
{
	struct rbn *rbn;

	RBT_FOREACH(rbn, &pool_targets) {
		struct pool_target_data *ptd;

		ptd = container_of(rbn, struct pool_target_data,
				   pool_targets_node);
		pool_target_sample(ctx, ptd->pool, ptd->target, ptd->metrics);
	}
}
