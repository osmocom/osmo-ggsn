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


static struct ippool_t *create_pool(const char *prefix_str, unsigned int flags)
{
	struct ippool_t *pool;
	struct in46_prefix pfx;
	size_t t;
	int rc;

	/* dynamic-only v4 */

	rc = ippool_aton(&pfx.addr, &t, prefix_str, flags);
	OSMO_ASSERT(rc == 0);
	pfx.prefixlen = t;

	rc = ippool_new(&pool, &pfx, NULL, flags);
	OSMO_ASSERT(rc == 0);

	//ippool_printaddr(pool);

	return pool;
}

static int test_pool_size(const char *pfx, unsigned int flags, unsigned int expected_size)
{
	struct ippool_t *pool;
	struct ippoolm_t *member;
	struct in46_addr addr;
	int i, rc, n;

	printf("testing pool for prefix %s, flags=0x%x, expected_size=%u\n", pfx, flags, expected_size);
	pool = create_pool(pfx, flags);
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

static int test_pool_sizes(void)
{
	struct ippool_t *pool;

	/* 256 addresses [0..255] */
	test_pool_size("192.168.23.0/24", 0, 256);

	/* 255 addresses [1..255] */
	test_pool_size("192.168.23.0/24", IPPOOL_NONETWORK, 255);

	/* 254 addresses [1..254] */
	test_pool_size("192.168.23.0/24", IPPOOL_NONETWORK | IPPOOL_NOBROADCAST, 254);

	/* 65534 addresses [0.1..255.254] */
	test_pool_size("192.168.0.0/16", IPPOOL_NONETWORK | IPPOOL_NOBROADCAST, 65534);

	/* 256 prefixes of /64 each */
	test_pool_size("2001:DB8::/56", 0, 256);
}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);

	srand(time(NULL));

	test_pool_sizes();
}
