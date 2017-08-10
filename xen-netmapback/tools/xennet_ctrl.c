/*
 *
 * Copyright (c) 2016-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Authors: Kenichi Yasukata
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <fcntl.h>
#include <string.h>
#include <xenctrl.h>
#include <xen/sys/privcmd.h>
#include <getopt.h>

#define D(fmt, ...) \
	fprintf(stderr, "%s        "fmt"\n", __func__, ##__VA_ARGS__)

#define XENNETOP_ctrl 8
#define XENNETOP_CTRL_SET_BDG_BATCH 1
#define XENNETOP_CTRL_SET_I40E_BUSY_WAIT 2
#define XENNETOP_CTRL_SET_CSCHED2_MIN_TIMER 3
#define XENNETOP_CTRL_SET_CSCHED2_CREDIT_INIT 4
#define XENNETOP_CTRL_SET_DRVDOM_TXSYNC 5

struct xennet_ctrl_op {
	int16_t id;
	int16_t op;
	uint64_t val1;
	int32_t val2;
};

static void
usage(void)
{
	fprintf(stderr,
	    "usage: a.out -b bridge_batch\n");
	exit(1);
}

int main(int argc, char **argv)
{
	int ch, fd, op = 0;
	struct xennet_ctrl_op dop;
	int val = -1;

	fprintf(stderr, "%s built %s %s\n",
		argv[0], __DATE__, __TIME__);

	while ( (ch = getopt(argc, argv, "v:o:")) != -1) {
		switch (ch) {
		default:
			D("bad option %c %s", ch, optarg);
			usage();
			break;
		case 'v':
			val = atoi(optarg);
			break;
		case 'o':
			op = atoi(optarg);
			break;
		}

	}

	if (val == -1) {
		usage();
	}

	switch (op) {
	case XENNETOP_CTRL_SET_BDG_BATCH:
		D("XENNETOP_CTRL_SET_BDG_BATCH");
		break;
	case XENNETOP_CTRL_SET_I40E_BUSY_WAIT:
		D("XENNETOP_CTRL_SET_I40E_BUSY_WAIT");
		break;
	case XENNETOP_CTRL_SET_CSCHED2_MIN_TIMER:
		D("XENNETOP_CTRL_SET_CSCHED2_MIN_TIMER");
		break;
	case XENNETOP_CTRL_SET_CSCHED2_CREDIT_INIT:
		D("XENNETOP_CTRL_SET_CSCHED2_CREDIT_INIT");
		break;
	case XENNETOP_CTRL_SET_DRVDOM_TXSYNC:
		D("XENNETOP_CTRL_SET_DRVDOM_TXSYNC");
		break;
	default:
		D("Invalid op %d", op);
		usage();
	}

	memset(&dop, 0, sizeof(struct xennet_ctrl_op));
	dop.op = op;
	dop.val1 = val;

	privcmd_hypercall_t my_hypercall = {
		41,
		{XENNETOP_ctrl, (unsigned long)&dop, 0, 0, 0}
	};

	if ((fd = open("/proc/xen/privcmd", O_RDWR)) < 0) {
		perror("open");
		exit(1);
	}

	ioctl(fd, IOCTL_PRIVCMD_HYPERCALL, &my_hypercall);

	return 0;
}
