#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/bits.h>

#include <osmocom/gtp/gtpie.h>

#include "../../lib/syserr.h"

static const uint8_t in[] = { 1,2,3,4,5,6 };
static uint8_t buf[256];
static int rc;

static void test_gtpie_tlv()
{
	unsigned int len = 0;

	printf("Testing gtpie_tlv()\n");

	/* normal / successful case */
	memset(buf, 0, sizeof(buf));
	rc = gtpie_tlv(buf, &len, sizeof(buf), 23, sizeof(in), in);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(len == sizeof(in) + 3);
	OSMO_ASSERT(buf[0] == 23);
	OSMO_ASSERT(osmo_load16be(&buf[1]) == sizeof(in));
	OSMO_ASSERT(!memcmp(buf+3, in, sizeof(in)));

	/* overflow */
	memset(buf, 0, sizeof(buf));
	rc = gtpie_tlv(buf, &len, 4, 23, sizeof(in), in);
	OSMO_ASSERT(rc == 1);
}

static void test_gtpie_tv0()
{
	unsigned int len = 0;

	printf("Testing gtpie_tv0()\n");

	memset(buf, 0, sizeof(buf));
	rc = gtpie_tv0(buf, &len, sizeof(buf), 42, sizeof(in), in);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(len == sizeof(in) + 1);
}

static void test_gtpie_tv1()
{
	unsigned int len = 0;

	printf("Testing gtpie_tv1()\n");

	memset(buf, 0, sizeof(buf));
	rc = gtpie_tv1(buf, &len, sizeof(buf), 42, 0xAD);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(len == 2);
	OSMO_ASSERT(buf[0] == 42);
	OSMO_ASSERT(buf[1] == 0xAD);
}

static void test_gtpie_tv2()
{
	unsigned int len = 0;

	printf("Testing gtpie_tv2()\n");

	memset(buf, 0, sizeof(buf));
	rc = gtpie_tv2(buf, &len, sizeof(buf), 42, 0xABCD);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(len == 3);
	OSMO_ASSERT(buf[0] == 42);
	OSMO_ASSERT(osmo_load16be(&buf[1]) == 0xABCD);
}

static void test_gtpie_tv4()
{
	unsigned int len = 0;

	printf("Testing gtpie_tv4()\n");

	memset(buf, 0, sizeof(buf));
	rc = gtpie_tv4(buf, &len, sizeof(buf), 42, 0xABCD0123);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(len == 5);
	OSMO_ASSERT(buf[0] == 42);
	OSMO_ASSERT(osmo_load32be(&buf[1]) == 0xABCD0123);
}

static void test_gtpie_tv8()
{
	unsigned int len = 0;

	printf("Testing gtpie_tv8()\n");

	memset(buf, 0, sizeof(buf));
	rc = gtpie_tv8(buf, &len, sizeof(buf), 42, 0x0001020304050607ULL);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(len == 9);
	OSMO_ASSERT(buf[0] == 42);
	OSMO_ASSERT(osmo_load32be(&buf[1]) == 0x00010203);
	OSMO_ASSERT(osmo_load32be(&buf[5]) == 0x04050607);
}

static void test_gtpie_getie(void)
{
	union gtpie_member *ie[GTPIE_SIZE] = {};
	union gtpie_member ie_elem[3] = {};

	printf("Testing gtpie_getie()\n");

	/* Empty ie should always return -1 */
	OSMO_ASSERT(gtpie_getie(ie, 0, 0) == -1);
	OSMO_ASSERT(gtpie_getie(ie, 0, 1) == -1);

	OSMO_ASSERT(gtpie_getie(ie, GTPIE_ENODEB_ID, 0) == -1);
	OSMO_ASSERT(gtpie_getie(ie, GTPIE_ENODEB_ID, 1) == -1);

	ie_elem[0].tv1.t = GTPIE_CAUSE;
	ie_elem[0].tv1.v = GTPIE_CAUSE;
	ie[0] = &ie_elem[0];

	OSMO_ASSERT(gtpie_getie(ie, GTPIE_CAUSE, 0) == 0);
	OSMO_ASSERT(gtpie_getie(ie, GTPIE_CAUSE, 1) == -1);


	ie_elem[1].tv1.t = GTPIE_CAUSE;
	ie_elem[1].tv1.v = GTPIE_CAUSE;
	ie[2] = &ie_elem[0];

	OSMO_ASSERT(gtpie_getie(ie, GTPIE_CAUSE, 0) == 0);
	OSMO_ASSERT(gtpie_getie(ie, GTPIE_CAUSE, 1) == 2);


	ie_elem[2].tv1.t = GTPIE_CAUSE;
	ie_elem[2].tv1.v = GTPIE_CAUSE;
	ie[GTPIE_SIZE - 1] = &ie_elem[0];

	OSMO_ASSERT(gtpie_getie(ie, GTPIE_CAUSE, 0) == 0);
	OSMO_ASSERT(gtpie_getie(ie, GTPIE_CAUSE, 1) == 2);
	OSMO_ASSERT(gtpie_getie(ie, GTPIE_CAUSE, 2) == GTPIE_SIZE - 1);
}


int main(int argc, char **argv)
{
	void *tall_ctx = talloc_named_const(NULL, 1, "Root context");
	msgb_talloc_ctx_init(tall_ctx, 0);
	osmo_init_logging2(tall_ctx, &log_info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);

	srand(time(NULL));

	test_gtpie_tlv();
	test_gtpie_tv0();
	test_gtpie_tv1();
	test_gtpie_tv2();
	test_gtpie_tv4();
	test_gtpie_tv8();

	test_gtpie_getie();

	/* TODO: gtpie_decaps() */
	/* TODO: gtpie_encaps() */
	/* TODO: gtpie_encaps2() */
	/* TODO: gtpie_exist(), gtpie_get*() */
	return 0;
}
