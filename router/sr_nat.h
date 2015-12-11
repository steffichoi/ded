
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_if.h"

#define MAX_HOSTS 256
/*only take in this many tcp sessions*/
#define FIN 1
#define SYN 2
#define RST 4
#define PSH 8
#define ACK 16
#define URG 32
#define ECE 64
#define CWR 128
#define NS 256
#define MAX_PACKET_VOL 1024

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
  CLOSE_WAIT, /*waiting for remote host to close session request*/
  CLOSED, /*DEFAULT, no session*/
  CLOSING,/*waiting for remote host to close session ACK*/
  ESTABLISHED,/*session is open*/
  FIN_WAIT_1,
  FIN_WAIT_2,
  LAST_ACK,
  LISTEN,/*waiting for connection request*/
  SYN_RECEIVED,
  SYN_SENT,
  TIME_WAIT
}STATES; /*TCP state machine*/

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t ip_dst;
  uint16_t port_dst;
  
  uint32_t ip_src;
  uint16_t port_src;

  STATES state; /*session status*/
  uint32_t LastReceivedAck; /*expected sequence should be this + 1*/
  uint8_t* packets;
  unsigned int len;
  int seq_no; /*actual sequence number*/
  int time_wait;

  int established;
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t time_wait; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;

  /* timeout values */
  uint16_t icmp_to;
  uint16_t tcp_establish_to;
  uint16_t tcp_transitory_to;

  uint16_t icmp_id;
  uint16_t tcp_id;

  struct sr_if *int_list;  /* internal interfaces */
  struct sr_if *ext_list;  /* external interfaces */

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

void sr_nat_refresh_mapping(struct sr_nat *nat, struct sr_nat_mapping *copy);

/* tcp connection functions */
int sr_nat_est_conn(struct sr_nat *nat, struct sr_nat_mapping *copy, 
  struct sr_nat_connection *con_copy);

void sr_nat_add_conn(struct sr_nat *nat, struct sr_nat_mapping *copy, uint32_t ip_src, 
  uint16_t port_src, uint32_t ip_dst, uint16_t port_dst, uint16_t seq_no, int established, 
  uint8_t *packet, unsigned int len);

struct sr_nat_connection *sr_nat_lookup_conn(struct sr_nat *nat, struct sr_nat_mapping *copy, 
  uint32_t ip_src, uint16_t port_src, uint32_t ip_dst, uint16_t port_dst);

void sr_nat_refresh_conn(struct sr_nat *nat, struct sr_nat_mapping *copy,
  struct sr_nat_connection *con_copy);

int sr_nat_update_seq_no(struct sr_nat *nat, struct sr_nat_mapping *copy, 
  struct sr_nat_connection *con_copy, uint16_t seq_no);

#endif