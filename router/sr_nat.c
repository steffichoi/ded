
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_protocol.h"

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  if (nat) {
    struct sr_nat_mapping *curr_map = nat->mappings;
    struct sr_nat_mapping *free_map = NULL;
    while(curr_map) {
      struct sr_nat_connection *conn = curr_map->conns;
      while (conn) {
        conn = conn->next;
        free(curr_map->conns);
        curr_map->conns = conn;
      }
      free_map = curr_map;
      curr_map = curr_map->next;
      free(free_map);
    }
  }
  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
  pthread_mutexattr_destroy(&(nat->attr));
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping* curr_map = nat->mappings;
  while(curr_map){
    if(curr_map->aux_ext == aux_ext && curr_map->type == type){
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, curr_map, sizeof(struct sr_nat_mapping));
    }
    curr_map = curr_map->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping* curr_map = nat->mappings;
  while(curr_map){
    if((curr_map->ip_int == ip_int) && (curr_map->aux_int == aux_int) && (curr_map->type == type){
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, curr_map, sizeof(struct sr_nat_mapping));
    }
    curr_map = curr_map->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat, uint32_t ip_int, 
  uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping));
  struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping));

  /* set mapping fields to insert */
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->ip_ext = nat->ext_list->ip;
  mapping->aux_int = aux_int;
  mapping->aux_ext = nat->aux_ext->ip;
  mapping->last_updated = time(NULL);
  mapping->conns = NULL;
  mapping->next = nat->mappings;

  if (type == nat_mapping_icmp) {
    mapping->aux_ext = nat->icmp_id;
    nat->icmp_id += 1;
  }
  else {  /* type is nat_mapping_tcp */
    mapping->aux_ext = nat->tcp_id;
    nat->tcp_id += 1;
    if (nat->tcp_id == 0){
      nat->tcp_id = 1024;
    }
  }
  nat->mappings = mapping;  
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

void sr_nat_refresh_mapping(struct sr_nat *nat, struct sr_nat_mapping *copy){
  pthread_mutex_lock(&(nat->lock));
  struct sr_nat_mapping* curr = nat->mappings;
  while(curr){
    if((curr->type == copy->type) && (curr->ip_int == copy->ip_int) && (curr->aux_int == copy->aux_int)){
      curr->last_updated = time(NULL);
      break;
    }
    curr = curr->next;
  }
  pthread_mutex_unlock(&(nat->lock));
}

uint8_t *sr_NAT_handle_send_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *iface) {
  sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));

  /* if it is coming from the internal interface */
  if (sr->nat && strcmp(iface, "eth1") == 0) {
    sr_nat_mapping_type packet_type;
    struct sr_nat_mapping *temp;

    if (ipHeader->ip_p == ip_protocol_icmp){
      packet_type = nat_mapping_icmp;
      sr_icmp_hdr_t *icmpHeader = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

      if (icmpHeader->icmp_code == 0 && icmpHeader->icmp_type == 8) {
        if (ipHeader->ip_dst == sr->nat->ext_list->ip) {    /* Drop packet */
          return NULL;
        }
        else if (ipHeader->ip_dst == sr->nat->int_list->ip) {
          sr_ethernet_hdr_t *ethHeader = (sr_ethernet_hdr_t *) packet;
          sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
          sr_icmp_hdr_t *icmpHeader = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

          struct sr_if* curr_iface =  sr_get_interface(sr, iface);
          if (curr_iface == NULL) return NULL;

          /* Set ethernet header and IP header for the new packet */
          set_addr(ethHeader, curr_iface->addr, ethHeader->ether_shost);

          ipHeader->ip_dst = ipHeader->ip_src;
          ipHeader->ip_src = curr_iface->ip;
          ipHeader->ip_ttl = 64;
          ipHeader->ip_sum = 0;
          ipHeader->ip_sum = cksum(ipHeader, sizeof(ipHeader));

          /* set icmp type 0 */
          uint16_t incm_cksum = icmpHeader->icmp_sum;
          icmpHeader->icmp_sum = 0;
          uint16_t currentChecksum = cksum(icmpHeader,len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

          if(currentChecksum == incm_cksum && icmpHeader->icmp_type == 8 && icmpHeader->icmp_code == 0) {
            icmpHeader->icmp_type = 0;
            ipHeader->ip_sum = 0;
            icmpHeader->icmp_sum = cksum(icmpHeader,len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
          }
          else{
            printf("ICMP INVALID\n");
            /* printf("%d != %d OR %d != %d\n",currentChecksum,incm_cksum, icmp_header->icmp_type, 8); */
          }
        }
      }
      temp = sr_nat_lookup_internal(sr->nat, ipHeader->ip_src, icmpHeader->icmp_id, packet_type);
      if (temp == NULL){
        temp = sr_nat_insert_mapping(sr->nat,ipHeader->ip_src, icmpHeader->icmp_id, packet_type);
      } else {
        sr_nat_refresh_mapping(sr->nat, temp);
      }
      ipHeader->ip_src = sr->nat->ext_list->ip;
      icmpHeader->icmp_id = temp->aux_ext;

      icmpHeader->icmp_sum = 0;
      icmpHeader->icmp_sum = cksum(icmpHeader, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

      free(temp);
    }

    else if(ipHeader->ip_p == ip_protocol_tcp){
      packet_type = nat_mapping_tcp;
      sr_tcp_hdr_t *tcpHeader = (sr_tcp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      
      temp = sr_nat_lookup_internal(sr->nat, ipHeader->ip_src, tcpHeader->source, packet_type);

      if (temp){
        sr_nat_refresh_mapping(sr->nat, temp);
      } else {
        temp = sr_nat_insert_mapping(sr->nat, ipHeader->ip_src, tcpHeader->source, packet_type);
      }

      /* look for an existing connection */
        /* if it is established update isn */
        /* if not then establish a connection */
        /* refrech connection timeout */
      /* no connection exists */
        /* do somehting?? check the syn and establish a connection */

      ipHeader->ip_src = sr->nat->ext_list->ip;
      
      tcpHeader->checksum = 0;
      tcpHeader->checksum = cksum(packet, len);
    }
    return packet;
  }
  return packet;
}

