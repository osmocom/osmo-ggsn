#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/bits.h>

#include "../../lib/in46_addr.h"
#include "../../lib/syserr.h"

static const struct in46_addr g_ia4 = {
	.len = 4,
	.v4.s_addr = 0x0d0c0b0a,
};

static void test_in46a_to_af(void)
{
	printf("Testing in46a_to_af() with IPv4 addresses\n");

	OSMO_ASSERT(in46a_to_af(&g_ia4) == AF_INET);
}

static void test_in46a_to_sas(void)
{
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *) &ss;

	printf("Testing in46a_to_sas() with IPv4 addresses\n");

	memset(&ss, 0, sizeof(ss));
	OSMO_ASSERT(in46a_to_sas(&ss, &g_ia4) == 0);
	OSMO_ASSERT(sin->sin_family == AF_INET);
	OSMO_ASSERT(sin->sin_addr.s_addr == g_ia4.v4.s_addr);
}

static void test_in46a_ntop(void)
{
	struct in46_addr ia;
	char buf[256];
	const char *res;

	printf("Testing in46a_ntop() with IPv4 addresses\n");

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

static void test_in46a_equal(void)
{
	struct in46_addr b;

	printf("Testing in46a_equal() with IPv4 addresses\n");

	memset(&b, 0xff, sizeof(b));
	b.len = g_ia4.len;
	b.v4.s_addr = g_ia4.v4.s_addr;
	OSMO_ASSERT(in46a_equal(&g_ia4, &b));
}

static int log_in46a_within_mask(const struct in46_addr *addr, const struct in46_addr *net,
				 size_t prefixlen)
{
	int rc;

	printf("in46a_within_mask(%s, ", in46a_ntoa(addr));
	printf("%s, %lu) = ", in46a_ntoa(net), prefixlen);

	rc = in46a_within_mask(addr, net, prefixlen);
	printf("%d\n", rc);

	return rc;
}

static void test_in46a_within_mask(void)
{
	struct in46_addr addr, mask;

	printf("Testing in46a_within_mask() with IPv4 addresses\n");

	addr = g_ia4;
	mask = g_ia4;
	OSMO_ASSERT(log_in46a_within_mask(&addr, &mask, 32));

	mask.v4.s_addr = htonl( ntohl(mask.v4.s_addr) & 0xfffffffC );
	OSMO_ASSERT(log_in46a_within_mask(&addr, &mask, 30));

	mask.v4.s_addr = htonl( ntohl(mask.v4.s_addr) & 0xfff80000 );
	OSMO_ASSERT(log_in46a_within_mask(&addr, &mask, 13));

	addr.v4.s_addr = htonl(ntohl(addr.v4.s_addr) + 1);
	mask = g_ia4;
	OSMO_ASSERT(!log_in46a_within_mask(&addr, &mask, 32));
	mask.v4.s_addr = htonl( ntohl(mask.v4.s_addr) & 0xfffffffC );
	OSMO_ASSERT(log_in46a_within_mask(&addr, &mask, 30));
}

static void test_in46a_to_eua(void)
{
	struct ul66_t eua;

	printf("testing in46a_to_eua() with IPv4 addresses\n");

#if 0	/* triggers assert in current implementation */
	const struct in46_addr ia_invalid = { .len = 3, };
	OSMO_ASSERT(in46a_to_eua(&ia_invalid, &eua) < 0);
#endif

	/* IPv4 address */
	OSMO_ASSERT(in46a_to_eua(&g_ia4, 1, &eua) == 0);
	OSMO_ASSERT(eua.v[0] == PDP_EUA_ORG_IETF);
	OSMO_ASSERT(eua.v[1] == PDP_EUA_TYPE_v4);
	OSMO_ASSERT(osmo_load32le(&eua.v[2]) == g_ia4.v4.s_addr);
}

static void test_in46a_from_eua(void)
{
	struct in46_addr ia;
	struct ul66_t eua;
	const uint8_t v4_unspec[] = { PDP_EUA_ORG_IETF, PDP_EUA_TYPE_v4 };
	const uint8_t v4_spec[] = { PDP_EUA_ORG_IETF, PDP_EUA_TYPE_v4, 1,2,3,4 };
	memset(&eua, 0, sizeof(eua));

	printf("Testing in46a_from_eua() with IPv4 addresses\n");

	/* default: v4 unspec */
	OSMO_ASSERT(in46a_from_eua(&eua, &ia) == 1);
	OSMO_ASSERT(ia.len == 4);
	OSMO_ASSERT(ia.v4.s_addr == 0);

	/* invalid */
	eua.v[0] = 0x23;
	eua.v[1] = PDP_EUA_TYPE_v4;
	eua.l = 6;
	OSMO_ASSERT(in46a_from_eua(&eua, &ia) < 0);

	/* invalid */
	eua.v[0] = PDP_EUA_ORG_IETF;
	eua.v[1] = 0x23;
	eua.l = 6;
	OSMO_ASSERT(in46a_from_eua(&eua, &ia) < 0);

	/* unspecified V4 */
	memcpy(eua.v, v4_unspec, sizeof(v4_unspec));
	eua.l = sizeof(v4_unspec);
	OSMO_ASSERT(in46a_from_eua(&eua, &ia) == 1);
	OSMO_ASSERT(ia.len == 4);
	OSMO_ASSERT(ia.v4.s_addr == 0);

	/* specified V4 */
	memcpy(eua.v, v4_spec, sizeof(v4_spec));
	eua.l = sizeof(v4_spec);
	OSMO_ASSERT(in46a_from_eua(&eua, &ia) == 1);
	OSMO_ASSERT(ia.len == 4);
	OSMO_ASSERT(ia.v4.s_addr == htonl(0x01020304));
}

static void test_in46a_netmasklen(void)
{
	struct in46_addr netmask;
	unsigned int len;

	printf("Testing in46a_netmasklen() with IPv4 addresses\n");
	netmask.len = 4;

	netmask.v4.s_addr = 0xffffffff;
	len = in46a_netmasklen(&netmask);
	OSMO_ASSERT(len == 32);

	netmask.v4.s_addr = 0x00ffffff;
	len = in46a_netmasklen(&netmask);
	OSMO_ASSERT(len == 24);

	netmask.v4.s_addr = 0x00f0ffff;
	len = in46a_netmasklen(&netmask);
	OSMO_ASSERT(len == 20);

	netmask.v4.s_addr = 0x000000fe;
	len = in46a_netmasklen(&netmask);
	OSMO_ASSERT(len == 7);

	netmask.v4.s_addr = 0x00000000;
	len = in46a_netmasklen(&netmask);
	OSMO_ASSERT(len == 0);
}

/* IPv6 specific tests */

static const struct in46_addr g_ia6 = {
	.len = 16,
	.v6.s6_addr = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 },
};

static void test_in46a_to_af_v6(void)
{
	struct in46_addr ia;

	printf("Testing in46a_to_af() with IPv6 addresses\n");

	OSMO_ASSERT(in46a_to_af(&g_ia6) == AF_INET6);

	ia.len = 8;
	OSMO_ASSERT(in46a_to_af(&ia) == AF_INET6);
}

static void test_in46a_to_sas_v6(void)
{
	struct sockaddr_storage ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &ss;

	printf("Testing in46a_to_sas() with IPv6 addresses\n");

	memset(&ss, 0, sizeof(ss));
	OSMO_ASSERT(in46a_to_sas(&ss, &g_ia6) == 0);
	OSMO_ASSERT(sin6->sin6_family == AF_INET6);
	OSMO_ASSERT(!memcmp(&sin6->sin6_addr, &g_ia6.v6, sizeof(sin6->sin6_addr)));
}

static void test_in46a_ntop_v6(void)
{
	char buf[256];
	const char *res;

	printf("Testing in46a_ntop() with IPv6 addresses\n");

	res = in46a_ntop(&g_ia6, buf, sizeof(buf));
	OSMO_ASSERT(res && !strcmp(res, "102:304:506:708:90a:b0c:d0e:f10"));
	printf("res = %s\n", res);
}

static void test_in46a_equal_v6(void)
{
	struct in46_addr b;

	printf("Testing in46a_equal() with IPv6 addresses\n");

	memset(&b, 0xff, sizeof(b));
	b.len = g_ia6.len;
	b.v6 = g_ia6.v6;
	OSMO_ASSERT(in46a_equal(&g_ia6, &b));
}

static void test_in46a_to_eua_v6(void)
{
	const struct in46_addr ia_v6_8 = {
		.len = 8,
		.v6.s6_addr = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 },
	};
	struct ul66_t eua;

	printf("Testing in46a_to_eua() with IPv6 addresses\n");

	/* IPv6 address */
	OSMO_ASSERT(in46a_to_eua(&g_ia6, 1, &eua) == 0);
	OSMO_ASSERT(eua.v[0] == PDP_EUA_ORG_IETF);
	OSMO_ASSERT(eua.v[1] == PDP_EUA_TYPE_v6);
	OSMO_ASSERT(!memcmp(&eua.v[2], &g_ia6.v6, 16));

	/* IPv6 address with prefix / length 8 */
	OSMO_ASSERT(in46a_to_eua(&ia_v6_8, 1, &eua) == 0);
	OSMO_ASSERT(eua.v[0] == PDP_EUA_ORG_IETF);
	OSMO_ASSERT(eua.v[1] == PDP_EUA_TYPE_v6);
	OSMO_ASSERT(!memcmp(&eua.v[2], &ia_v6_8.v6, 16));
}

static void test_in46a_to_eua_v4v6() {
	const struct in46_addr ia_v4v6[2] = {
		{
		.len = 16,
		.v6.s6_addr = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 },
		},
		{
		.len = 4,
		.v4.s_addr = 0x0d0c0b0a,
		}
	};
	struct ul66_t eua;
	printf("Testing in46a_to_eua() with IPv4v6 addresses\n");

	/* IPv4 address */
	OSMO_ASSERT(in46a_to_eua(ia_v4v6, 2, &eua) == 0);
	OSMO_ASSERT(eua.v[0] == PDP_EUA_ORG_IETF);
	OSMO_ASSERT(eua.v[1] == PDP_EUA_TYPE_v4v6);
	OSMO_ASSERT(osmo_load32le(&eua.v[2]) == g_ia4.v4.s_addr);
	OSMO_ASSERT(!memcmp(&eua.v[6], &g_ia6.v6, 16));
}

static void test_in46a_from_eua_v6(void)
{
	struct in46_addr ia;
	struct ul66_t eua;
	const uint8_t v6_unspec[] = { PDP_EUA_ORG_IETF, PDP_EUA_TYPE_v6 };
	const uint8_t v6_spec[] = { PDP_EUA_ORG_IETF, PDP_EUA_TYPE_v6,
				    1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,0x10 };

	memset(&eua, 0, sizeof(eua));

	printf("Testing in46a_from_eua() with IPv6 addresses\n");

	/* unspecified V6 */
	memcpy(eua.v, v6_unspec, sizeof(v6_unspec));
	eua.l = sizeof(v6_unspec);
	OSMO_ASSERT(in46a_from_eua(&eua, &ia) == 1);
	OSMO_ASSERT(ia.len == 16);
	OSMO_ASSERT(IN6_IS_ADDR_UNSPECIFIED(&ia.v6));

	/* specified V6 */
	memcpy(eua.v, v6_spec, sizeof(v6_spec));
	eua.l = sizeof(v6_spec);
	OSMO_ASSERT(in46a_from_eua(&eua, &ia) == 1);
	OSMO_ASSERT(ia.len == 16);
	OSMO_ASSERT(!memcmp(&ia.v6, v6_spec+2, ia.len));
}

static void test_in46a_from_eua_v4v6(void) {
	struct in46_addr ia[2];
	struct ul66_t eua;
	const uint8_t v4_unspec_v6_unspec[] = { PDP_EUA_ORG_IETF, PDP_EUA_TYPE_v4v6 };
	const uint8_t v4_spec_v6_unspec[] = { PDP_EUA_ORG_IETF, PDP_EUA_TYPE_v4v6, 1,2,3,4 };
	const uint8_t v4_unspec_v6_spec[] = { PDP_EUA_ORG_IETF, PDP_EUA_TYPE_v4v6, 1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,0x10 };
	const uint8_t v4_spec_v6_spec[] = { PDP_EUA_ORG_IETF, PDP_EUA_TYPE_v4v6, 1,2,3,4, 1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,0x10 };

	memset(&eua, 0, sizeof(eua));

	printf("Testing in46a_from_eua() with IPv4v6 addresses\n");

	/* unspecified V4 & V6 */
	memcpy(eua.v, v4_unspec_v6_unspec, sizeof(v4_unspec_v6_unspec));
	eua.l = sizeof(v4_unspec_v6_unspec);
	OSMO_ASSERT(in46a_from_eua(&eua, ia) == 2);
	OSMO_ASSERT(ia[0].len == 4);
	OSMO_ASSERT(ia[1].len == 16);
	OSMO_ASSERT(ia[0].v4.s_addr == 0);
	OSMO_ASSERT(IN6_IS_ADDR_UNSPECIFIED(&ia[1].v6));

	/* specified V4, unspecified V6 */
	memcpy(eua.v, v4_spec_v6_unspec, sizeof(v4_spec_v6_unspec));
	eua.l = sizeof(v4_spec_v6_unspec);
	OSMO_ASSERT(in46a_from_eua(&eua, ia) == 2);
	OSMO_ASSERT(ia[0].len == 4);
	OSMO_ASSERT(ia[1].len == 16);
	OSMO_ASSERT(ia[0].v4.s_addr == htonl(0x01020304));
	OSMO_ASSERT(IN6_IS_ADDR_UNSPECIFIED(&ia[1].v6));

	/* unspecified V4, specified V6 */
	memcpy(eua.v, v4_unspec_v6_spec, sizeof(v4_unspec_v6_spec));
	eua.l = sizeof(v4_unspec_v6_spec);
	OSMO_ASSERT(in46a_from_eua(&eua, ia) == 2);
	OSMO_ASSERT(ia[0].len == 4);
	OSMO_ASSERT(ia[1].len == 16);
	OSMO_ASSERT(ia[0].v4.s_addr == 0);
	OSMO_ASSERT(!memcmp(&ia[1].v6, v4_unspec_v6_spec+2, ia[1].len));

	/* specified V4, specified V6 */
	memcpy(eua.v, v4_spec_v6_spec, sizeof(v4_spec_v6_spec));
	eua.l = sizeof(v4_spec_v6_spec);
	OSMO_ASSERT(in46a_from_eua(&eua, ia) == 2);
	OSMO_ASSERT(ia[0].len == 4);
	OSMO_ASSERT(ia[1].len == 16);
	OSMO_ASSERT(ia[0].v4.s_addr == htonl(0x01020304));
	OSMO_ASSERT(!memcmp(&ia[1].v6, v4_spec_v6_spec+6, ia[1].len));
}

static void test_in46a_netmasklen_v6(void)
{
	unsigned int len;
	printf("Testing in46a_netmasklen() with IPv6 addresses\n");
	const struct in46_addr netmaskA = {
		.len = 16,
		.v6.s6_addr = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
	};
	len = in46a_netmasklen(&netmaskA);
	OSMO_ASSERT(len == 128);

	const struct in46_addr netmaskB = {
		.len = 16,
		.v6.s6_addr = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00},
	};
	len = in46a_netmasklen(&netmaskB);
	OSMO_ASSERT(len == 104);

	const struct in46_addr netmaskC = {
		.len = 16,
		.v6.s6_addr = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0x00,0x00,0x00},
	};
	len = in46a_netmasklen(&netmaskC);
	OSMO_ASSERT(len == 103);

	const struct in46_addr netmaskD = {
		.len = 16,
		.v6.s6_addr = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
	};
	len = in46a_netmasklen(&netmaskD);
	OSMO_ASSERT(len == 0);
}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);

	srand(time(NULL));

	if (argc < 2 || strcmp(argv[1], "-v6")) {
		test_in46a_to_af();
		test_in46a_to_sas();
		test_in46a_ntop();
		test_in46p_ntoa();
		test_in46a_equal();
		test_in46a_within_mask();
		test_in46a_to_eua();
		test_in46a_from_eua();
		test_in46a_netmasklen();
	} else {
		test_in46a_to_af_v6();
		test_in46a_to_sas_v6();
		test_in46a_ntop_v6();
		test_in46a_equal_v6();
		test_in46a_to_eua_v6();
		test_in46a_from_eua_v6();
		test_in46a_to_eua_v4v6();
		test_in46a_from_eua_v4v6();
		test_in46a_netmasklen_v6();
	}
	return 0;
}
