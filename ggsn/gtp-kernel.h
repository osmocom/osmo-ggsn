#ifndef _GTP_KERNEL_H_
#define _GTP_KERNEL_H_

struct gengetopt_args_info;

extern int debug;
extern char *ipup;

#ifdef GTP_KERNEL
int gtp_kernel_init(struct gsn_t *gsn, struct in_addr *net,
		    size_t prefixlen, const char *net_arg);
void gtp_kernel_stop(void);

int gtp_kernel_tunnel_add(struct pdp_t *pdp);
int gtp_kernel_tunnel_del(struct pdp_t *pdp);

int gtp_kernel_enabled(void);

#else
static inline int gtp_kernel_init(struct gsn_t *gsn, struct in_addr *net,
				  size_t prefixlen, const char *net_arg)
{
	SYS_ERR(DGGSN, LOGL_ERROR, 0, "ggsn compiled without GTP kernel support!\n");
	return -1;
}

static inline void gtp_kernel_stop(void) {}

static inline int gtp_kernel_tunnel_add(struct pdp_t *pdp)
{
	return 0;
}

static inline int gtp_kernel_tunnel_del(struct pdp_t *pdp)
{
	return 0;
}

static inline int gtp_kernel_enabled(void)
{
	return 0;
}

#endif
#endif /* _GTP_KERNEL_H_ */
