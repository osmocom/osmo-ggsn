#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>

#include "../../lib/in46_addr.h"
#include "../../lib/ippool.h"
#include "../../lib/syserr.h"


static struct ippool_t *create_pool(const char *prefix_str, unsigned int flags, char **blacklist, size_t blacklist_size)
{
	struct in46_prefix *blacklist_pfx;
	struct ippool_t *pool;
	struct in46_prefix pfx;
	size_t t;
	int rc;
	int i;

	blacklist_pfx = calloc(blacklist_size, sizeof(struct in46_prefix));
	for (i = 0; i < blacklist_size; i++) {
		rc = ippool_aton(&blacklist_pfx[i].addr, &t, blacklist[i], 0);
		OSMO_ASSERT(rc == 0);
		pfx.prefixlen = t;
	}

	/* dynamic-only v4 */

	rc = ippool_aton(&pfx.addr, &t, prefix_str, 0);
	OSMO_ASSERT(rc == 0);
	pfx.prefixlen = t;

	rc = ippool_new(&pool, &pfx, NULL, flags, blacklist_pfx, blacklist_size);
	OSMO_ASSERT(rc == 0);

	//ippool_printaddr(pool);

	free(blacklist_pfx);

	return pool;
}

static void test_pool_size(const char *pfx, unsigned int flags, char **blacklist, size_t blacklist_size, unsigned int expected_size)
{
	struct ippool_t *pool;
	struct ippoolm_t *member;
	struct in46_addr addr;
	int i, rc, n;

	printf("testing pool for prefix %s, flags=0x%x, blacklist_size=%lu, expected_size=%u\n", pfx, flags, blacklist_size, expected_size);
	pool = create_pool(pfx, flags, blacklist, blacklist_size);
	OSMO_ASSERT(pool->listsize == expected_size);

	memset(&addr, 0, sizeof(addr));
	addr.len = pool->member[0].addr.len;

	/* allocate all addresses */
	for (i = 0; i < expected_size; i++) {
		member = NULL;
		rc = ippool_newip(pool, &member, &addr, 0);
		OSMO_ASSERT(rc == 0);
		OSMO_ASSERT(member);
		printf("allocated address %s\n", in46a_ntoa(&member->addr));
	}
	/* allocate one more, expect that to fail */
	rc = ippool_newip(pool, &member, &addr, 0);
	OSMO_ASSERT(rc < 0);

	/* release a (random) number N of (random) member address */
	n = rand() % pool->listsize;
	for (i = 0; i < n; i++) {
		int r;
		/* chose a random index that is in use */
		do {
			r = rand() % pool->listsize;
		} while (!pool->member[r].inuse);
		/* and free it... */
		rc = ippool_freeip(pool, &pool->member[r]);
		OSMO_ASSERT(rc == 0);
	}

	/* allocate all N previously released addresses */
	for (i = 0; i < n; i++) {
		member = NULL;
		rc = ippool_newip(pool, &member, &addr, 0);
		OSMO_ASSERT(rc == 0);
		OSMO_ASSERT(member);
	}

	/* allocate one more, expect that to fail */
	rc = ippool_newip(pool, &member, &addr, 0);
	OSMO_ASSERT(rc < 0);

	ippool_free(pool);
}

static void test_pool_sizes(void)
{
	/* 256 addresses [0..255] */
	test_pool_size("192.168.23.0/24", 0, NULL, 0, 256);

	/* 255 addresses [1..255] */
	test_pool_size("192.168.23.0/24", IPPOOL_NONETWORK, NULL, 0, 255);

	/* 254 addresses [1..254] */
	test_pool_size("192.168.23.0/24", IPPOOL_NONETWORK | IPPOOL_NOBROADCAST, NULL, 0, 254);

	/* 65534 addresses [0.1..255.254] */
	test_pool_size("192.168.0.0/16", IPPOOL_NONETWORK | IPPOOL_NOBROADCAST, NULL, 0, 65534);

	/* 253 addresses [1..254] & exclude 192.168.23.1/24 */
	char *blacklist[] = {"176.16.222.10/24", "192.168.23.1/24", "192.168.38.2/24"};
	test_pool_size("192.168.23.0/24", IPPOOL_NONETWORK | IPPOOL_NOBROADCAST, blacklist, 3, 253);
}

static void test_pool_sizes_v6(void)
{
	/* 256 prefixes of /64 each */
	test_pool_size("2001:DB8::/56", 0, NULL, 0, 256);
}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);

	srand(time(NULL));

	if (argc < 2 || strcmp(argv[1], "-v6")) {
		test_pool_sizes();
	} else {
		test_pool_sizes_v6();
	}
	return 0;
}
