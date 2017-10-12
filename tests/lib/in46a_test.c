#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>

#include "../../lib/in46_addr.h"
#include "../../lib/syserr.h"

static void test_in46a_to_af(void)
{
	struct in46_addr ia;

	printf("Testing in46a_to_af()\n");

	ia.len = 4;
	OSMO_ASSERT(in46a_to_af(&ia) == AF_INET);
	ia.len = 8;
	OSMO_ASSERT(in46a_to_af(&ia) == AF_INET6);
	ia.len = 16;
	OSMO_ASSERT(in46a_to_af(&ia) == AF_INET6);
}

static void test_in46a_to_sas(void)
{
	struct in46_addr ia;
	struct sockaddr_storage ss;

	printf("Testing in46a_to_sas()\n");

	//FIXME;
	OSMO_ASSERT(in46a_to_sas(&ss, &ia));
}

static void test_in46a_ntop(void)
{
	struct in46_addr ia;
	char buf[256];
	const char *res;

	printf("Testing in46a_ntop()\n");

	res = in46a_ntop(NULL, buf, sizeof(buf));
	OSMO_ASSERT(res && !strcmp(res, "UNDEFINED"));
	printf("res = %s\n", res);

	ia.len = 0;
	res = in46a_ntop(&ia, buf, sizeof(buf));
	printf("res = %s\n", res);
	OSMO_ASSERT(res && !strcmp(res, "UNDEFINED"));

	ia.len = 4;
	ia.v4.s_addr = htonl(0x01020304);
	res = in46a_ntop(&ia, buf, sizeof(buf));
	OSMO_ASSERT(res && !strcmp(res, "1.2.3.4"));
	printf("res = %s\n", res);

	/* FIXME: ipv6 */
}

static void test_in46p_ntoa(void)
{
	const struct in46_prefix ip46 = {
		.prefixlen = 24,
		.addr = {
			.len = 4,
			.v4.s_addr = htonl(0x10203000),
		},
	};
	printf("in46p_ntoa() returns %s\n", in46p_ntoa(&ip46));
}

static void test_in46a_eua(void)
{

}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);

	srand(time(NULL));

	test_in46a_to_af();
	test_in46a_ntop();
	test_in46p_ntoa();
}
