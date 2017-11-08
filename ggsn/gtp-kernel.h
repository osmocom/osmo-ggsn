#ifndef _GTP_KERNEL_H_
#define _GTP_KERNEL_H_

struct gengetopt_args_info;

extern int debug;
extern char *ipup;

#ifdef GTP_KERNEL
int gtp_kernel_init(struct gsn_t *gsn, const char *devname, struct in46_prefix *prefix, const char *ipup);
void gtp_kernel_stop(const char *devname);

int gtp_kernel_tunnel_add(struct pdp_t *pdp, const char *devname);
int gtp_kernel_tunnel_del(struct pdp_t *pdp, const char *devname);

int gtp_kernel_enabled(void);

#else
static inline int gtp_kernel_init(struct gsn_t *gsn, const char *devname, struct in46_prefix *prefix, const char *ipup)
{
	SYS_ERR(DGGSN, LOGL_ERROR, 0, "ggsn compiled without GTP kernel support!\n");
	return -1;
}

static inline void gtp_kernel_stop(const char *devname) {}

static inline int gtp_kernel_tunnel_add(struct pdp_t *pdp, const char *devname)
{
	return 0;
}

static inline int gtp_kernel_tunnel_del(struct pdp_t *pdp, const char *devname)
{
	return 0;
}

static inline int gtp_kernel_enabled(void)
{
	return 0;
}

#endif
#endif /* _GTP_KERNEL_H_ */
