#ifndef _GTP_KERNEL_H_
#define _GTP_KERNEL_H_

struct gengetopt_args_info;

extern int debug;
extern char *ipup;

#ifdef GTP_KERNEL
int gtp_kernel_create(int dest_ns, const char *devname, int fd0, int fd1u);
int gtp_kernel_create_sgsn(int dest_ns, const char *devname, int fd0, int fd1u);
void gtp_kernel_stop(const char *devname);

int gtp_kernel_tunnel_add(struct pdp_t *pdp, const char *devname);
int gtp_kernel_tunnel_del(struct pdp_t *pdp, const char *devname);

#else
static inline int gtp_kernel_create(int dest_ns, const char *devname, int fd0, int fd1u)
{
	SYS_ERR(DGGSN, LOGL_ERROR, 0, "ggsn compiled without GTP kernel support!\n");
	return -1;
}
#define gtp_kernel_create_sgsn gtp_kernel_create

static inline void gtp_kernel_stop(const char *devname) {}

static inline int gtp_kernel_tunnel_add(struct pdp_t *pdp, const char *devname)
{
	return 0;
}

static inline int gtp_kernel_tunnel_del(struct pdp_t *pdp, const char *devname)
{
	return 0;
}

#endif
#endif /* _GTP_KERNEL_H_ */
