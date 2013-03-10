/*
 * Copyright (c) 2011 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2011 Sandia Corporation. All rights reserved.
 * Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 * license for use of this work by or on behalf of the U.S. Government.
 * Export of this program may require a license from the United States
 * Government.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of Sandia nor the names of any contributors may
 *      be used to endorse or promote products derived from this software
 *      without specific prior written permission. 
 *
 *      Neither the name of Open Grid Computing nor the names of any
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission. 
 *
 *      Modified source versions must be plainly marked as such, and
 *      must not be misrepresented as being the original software.    
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Author: Tom Tucker <tom@opengridcomputing.com>
 */
/**
 * \file meminfo.c
 * \brief /proc/meminfo data provider
 */
#define _GNU_SOURCE
#include <inttypes.h>
#include <unistd.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <pthread.h>
#include "ldms.h"
#include "ldmsd.h"

#define PROC_FILE "/proc/meminfo"

static char *procfile = PROC_FILE;
static uint64_t counter;
ldms_set_t set;
FILE *mf;
ldms_metric_t *metric_table;
ldmsd_msg_log_f msglog;
union ldms_value comp_id;
ldms_metric_t compid_metric_handle;
ldms_metric_t counter_metric_handle;
ldms_metric_t tv_sec_metric_handle;
ldms_metric_t tv_nsec_metric_handle;

#undef CHECK_MEMINFO_TIMING
#ifdef CHECK_MEMINFO_TIMING
//Some temporary for testing
ldms_metric_t tv_sec_metric_handle2;
ldms_metric_t tv_nsec_metric_handle2;
ldms_metric_t tv_dnsec_metric_handle;
#endif


static int create_metric_set(const char *path)
{
	size_t meta_sz, tot_meta_sz;
	size_t data_sz, tot_data_sz;
	int rc, i, metric_count;
	uint64_t metric_value;
	//	union ldms_value v;
	char *s;
	char lbuf[256];
	char metric_name[128];
	char junk[128];

	mf = fopen(procfile, "r");
	if (!mf) {
		msglog("Could not open the meminfo file '%s'...exiting\n", procfile);
		return ENOENT;
	}

	/*
	 * Process the file once first to determine the metric set size.
	 */

	rc = ldms_get_metric_size("component_id", LDMS_V_U64,
				  &tot_meta_sz, &tot_data_sz);


	rc = ldms_get_metric_size("meminfo_counter", LDMS_V_U64, &meta_sz, &data_sz);
	tot_meta_sz += meta_sz;
	tot_data_sz += data_sz;

	rc = ldms_get_metric_size("meminfo_tv_sec", LDMS_V_U64, &meta_sz, &data_sz);
	tot_meta_sz += meta_sz;
	tot_data_sz += data_sz;

	rc = ldms_get_metric_size("meminfo_tv_nsec", LDMS_V_U64, &meta_sz, &data_sz);
	tot_meta_sz += meta_sz;
	tot_data_sz += data_sz;

	metric_count = 0;
	fseek(mf, 0, SEEK_SET);
	do {
		s = fgets(lbuf, sizeof(lbuf), mf);
		if (!s)
			break;
		rc = sscanf(lbuf, "%s %" PRIu64 " %s\n", metric_name,
			    &metric_value, junk);
		if (rc < 2)
			break;
		/* Strip the colon from metric name if present */
		i = strlen(metric_name);
		if (i && metric_name[i-1] == ':')
			metric_name[i-1] = '\0';

		rc = ldms_get_metric_size(metric_name, LDMS_V_U64,
					  &meta_sz, &data_sz);
		if (rc)
			return rc;

		tot_meta_sz += meta_sz;
		tot_data_sz += data_sz;
		metric_count++;
	} while (s);
	

	rc = ldms_get_metric_size("meminfo_tv_sec2", LDMS_V_U64, &meta_sz, &data_sz);
	tot_meta_sz += meta_sz;
	tot_data_sz += data_sz;

	rc = ldms_get_metric_size("meminfo_tv_nsec2", LDMS_V_U64, &meta_sz, &data_sz);
	tot_meta_sz += meta_sz;
	tot_data_sz += data_sz;

	rc = ldms_get_metric_size("meminfo_tv_dnsec", LDMS_V_U64, &meta_sz, &data_sz);
	tot_meta_sz += meta_sz;
	tot_data_sz += data_sz;


	/* Create the metric set */
	rc = ENOMEM;
	rc = ldms_create_set(path, tot_meta_sz, tot_data_sz, &set);
	if (rc)
		return rc;

	metric_table = calloc(metric_count, sizeof(ldms_metric_t));
	if (!metric_table)
		goto err;
	/*
	 * Process the file again to define all the metrics.
	 */
	compid_metric_handle = ldms_add_metric(set, "component_id", LDMS_V_U64);
	if (!compid_metric_handle)
		goto err;

	counter_metric_handle = ldms_add_metric(set, "meminfo_counter", LDMS_V_U64);
	if (!counter_metric_handle)
		goto err;

	tv_sec_metric_handle = ldms_add_metric(set, "meminfo_tv_sec", LDMS_V_U64);
	if (!tv_sec_metric_handle)
		goto err;

	tv_nsec_metric_handle = ldms_add_metric(set, "meminfo_tv_nsec", LDMS_V_U64);
	if (!tv_nsec_metric_handle)
		goto err;

	int metric_no = 0;
	fseek(mf, 0, SEEK_SET);
	do {
		s = fgets(lbuf, sizeof(lbuf), mf);
		if (!s)
			break;
		rc = sscanf(lbuf, "%s %" PRIu64 " %s\n",
			    metric_name, &metric_value, junk);
		if (rc < 2)
			break;
		/* Strip the colon from metric name if present */
		i = strlen(metric_name);
		if (i && metric_name[i-1] == ':')
			metric_name[i-1] = '\0';

		metric_table[metric_no] = ldms_add_metric(set, metric_name, LDMS_V_U64);
		if (!metric_table[metric_no]) {
			rc = ENOMEM;
			goto err;
		}
		metric_no++;
	} while (s);


#ifdef CHECK_MEMINFO_TIMING
	tv_sec_metric_handle2 = ldms_add_metric(set, "meminfo_tv_sec2", LDMS_V_U64);
	if (!tv_sec_metric_handle)
		goto err;

	tv_nsec_metric_handle2 = ldms_add_metric(set, "meminfo_tv_nsec2", LDMS_V_U64);
	if (!tv_nsec_metric_handle)
		goto err;

	tv_dnsec_metric_handle = ldms_add_metric(set, "meminfo_tv_dnsec", LDMS_V_U64);
	if (!tv_dnsec_metric_handle)
		goto err;
#endif


	return 0;

 err:
	ldms_set_release(set);
	return rc;
}

/** 
 * \brief Configuration
 *
 * config name=meminfo component_id=<comp_id> set=<setname>
 *     comp_id     The component id value.
 *     setname     The set name.
 */
static int config(struct attr_value_list *kwl, struct attr_value_list *avl)
{
	char *value;

	value = av_value(avl, "component_id");
	if (value)
		comp_id.v_u64 = strtol(value, NULL, 0);
	
	value = av_value(avl, "set");
	if (value)
		create_metric_set(value);

	return 0;
}

static ldms_set_t get_set()
{
	return set;
}

static int sample(void)
{
	int rc;
	int metric_no;
	char *s;
	char lbuf[256];
	char metric_name[128];
	char junk[128];
	union ldms_value v;
	struct timespec time1;

#ifdef CHECK_MEMINFO_TIMING
	uint64_t beg_nsec; //testing
#endif

	if (!set) {
		msglog("meminfo: plugin not initialized\n");
		return EINVAL;
	}
	ldms_set_metric(compid_metric_handle, &comp_id);

	//set the counter
	v.v_u64 = ++counter;
	ldms_set_metric(counter_metric_handle, &v);

	clock_gettime(CLOCK_REALTIME, &time1);
	v.v_u64 = time1.tv_sec;
	ldms_set_metric(tv_sec_metric_handle, &v);
#ifdef CHECK_MEMINFO_TIMING
	beg_nsec = time1.tv_nsec;
#endif
	v.v_u64 = time1.tv_nsec;
	ldms_set_metric(tv_nsec_metric_handle, &v);
	

	metric_no = 0;
	fseek(mf, 0, SEEK_SET);
	do {
		s = fgets(lbuf, sizeof(lbuf), mf);
		if (!s)
			break;
		rc = sscanf(lbuf, "%s %"PRIu64 " %s\n", metric_name, &v.v_u64, junk);
		if (rc != 2 && rc != 3)
			return EINVAL;

		ldms_set_metric(metric_table[metric_no], &v);
		metric_no++;
	} while (s);

#ifdef CHECK_MEMINFO_TIMING
	clock_gettime(CLOCK_REALTIME, &time1);
	v.v_u64 = time1.tv_sec;
	ldms_set_metric(tv_sec_metric_handle2, &v);
	v.v_u64 = time1.tv_nsec;
	ldms_set_metric(tv_nsec_metric_handle2, &v);
	v.v_u64 = time1.tv_nsec - beg_nsec;
	ldms_set_metric(tv_dnsec_metric_handle, &v);
#endif

 	return 0;
}

static void term(void)
{
	if (set)
		ldms_destroy_set(set);
	set = NULL;
}

static const char *usage(void)
{
	return  "config name=meminfo component_id=<comp_id> set=<setname>\n"
		"    comp_id     The component id value.\n"
		"    setname     The set name.\n";
}

static struct ldmsd_sampler meminfo_plugin = {
	.base = {
		.name = "meminfo",
		.term = term,
		.config = config,
		.usage = usage,
	},
	.get_set = get_set,
	.sample = sample,
};

struct ldmsd_plugin *get_plugin(ldmsd_msg_log_f pf)
{
	msglog = pf;
	return &meminfo_plugin.base;
}
