#pragma once

int gtp_echo_resp(struct gsn_t *gsn, int version,
		  struct sockaddr_in *peer, int fd,
		  void *pack, unsigned len);
int gtp_echo_ind(struct gsn_t *gsn, int version,
		 struct sockaddr_in *peer, int fd,
		 void *pack, unsigned len);
int gtp_echo_conf(struct gsn_t *gsn, int version,
		  struct sockaddr_in *peer, void *pack, unsigned len);

int gtp_unsup_req(struct gsn_t *gsn, int version,
		  struct sockaddr_in *peer,
		  int fd, void *pack, unsigned len);
int gtp_unsup_ind(struct gsn_t *gsn, struct sockaddr_in *peer,
		  void *pack, unsigned len);

int gtp_create_pdp_resp(struct gsn_t *gsn, int version,
			struct pdp_t *pdp, uint8_t cause);

int gtp_create_pdp_ind(struct gsn_t *gsn, int version,
		       struct sockaddr_in *peer, int fd,
		       void *pack, unsigned len);

int gtp_create_pdp_conf(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer,
			void *pack, unsigned len);

int gtp_update_pdp_req(struct gsn_t *gsn, int version, void *cbp,
		       struct in_addr *inetaddr, struct pdp_t *pdp);

int gtp_delete_pdp_req(struct gsn_t *gsn, int version, void *cbp,
		       struct pdp_t *pdp);

int gtp_delete_pdp_resp(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer, int fd,
			void *pack, unsigned len,
			struct pdp_t *pdp, struct pdp_t *linked_pdp,
			uint8_t cause, int teardown);

int gtp_delete_pdp_ind(struct gsn_t *gsn, int version,
		       struct sockaddr_in *peer, int fd,
		       void *pack, unsigned len);

int gtp_delete_pdp_conf(struct gsn_t *gsn, int version,
			struct sockaddr_in *peer,
			void *pack, unsigned len);

int ipv42eua(struct ul66_t *eua, struct in_addr *src);
int eua2ipv4(struct in_addr *dst, struct ul66_t *eua);
int in_addr2gsna(struct ul16_t *gsna, struct in_addr *src);
uint64_t gtp_imsi_str2gtp(const char *str);
