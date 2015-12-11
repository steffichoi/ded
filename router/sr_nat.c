
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
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ){

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping* curr_map = nat->mappings;
  while(curr_map) {
    if((curr_map->ip_int == ip_int) && (curr_map->aux_int == aux_int) && (curr_map->type == type)) {
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
  mapping->last_updated = time(NULL);
  mapping->conns = NULL;
  mapping->next = nat->mappings;

  nat->mappings = mapping;  
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

void sr_nat_refresh_mapping(struct sr_nat *nat, struct sr_nat_mapping *copy){
  pthread_mutex_lock(&(nat->lock));
  struct sr_nat_mapping* curr_map = nat->mappings;
  while(curr_map){
    if((curr_map->type == copy->type) && (curr_map->ip_int == copy->ip_int) && (curr_map->aux_int == copy->aux_int)){
      curr_map->last_updated = time(NULL);
      break;
    }
    curr_map = curr_map->next;
  }
  pthread_mutex_unlock(&(nat->lock));
}

/* tcp functions! */
int sr_nat_est_conn(struct sr_nat *nat, struct sr_nat_mapping *copy, 
  struct sr_nat_connection *con_copy) {
  
  pthread_mutex_lock(&(nat->lock));
  struct sr_nat_mapping* curr_map = nat->mappings;
  while(curr_map){
    if((curr_map->type == copy->type) && (curr_map->ip_int == copy->ip_int) && (curr_map->aux_int == copy->aux_int)){
      struct sr_nat_connection* con = curr_map->conns;
      while (con){
        if (con->ip_src == con_copy->ip_src && con->port_src == con_copy->port_src && con->ip_dst == con_copy->ip_dst && con->port_dst == con_copy->port_dst){
          con->established = 1;
          if (con->packets) {
            free(con->packets);
            con->len = 0;
          }
          pthread_mutex_unlock(&(nat->lock));
          return 1;
        }
        con = con->next;
      }
    break;
    }
  curr_map = curr_map->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return 0;
}

void sr_nat_add_conn(struct sr_nat *nat, struct sr_nat_mapping *copy, uint32_t ip_src, 
  uint16_t port_src, uint32_t ip_dst, uint16_t port_dst, uint16_t seq_no, int established, 
  uint8_t *packet, unsigned int len) {

  pthread_mutex_lock(&(nat->lock));
  struct sr_nat_mapping* curr_map = nat->mappings;
  while(curr_map){
    if((curr_map->type == copy->type) && (curr_map->ip_int == copy->ip_int) && (curr_map->aux_int == copy->aux_int)){
      struct sr_nat_connection *new_con = malloc(sizeof(struct sr_nat_connection));
      new_con->ip_src = ip_src;
      new_con->port_src = port_src;
      new_con->ip_dst = ip_dst;
      new_con->port_dst = port_dst;
      new_con->seq_no = seq_no;
      new_con->established = established;
      new_con->packets = packet;
      new_con->len = len;
      new_con->time_wait = time(NULL);
      new_con->next = curr_map->conns;
      curr_map->conns = new_con;
      break;
    }
    curr_map = curr_map->next;
  }
  pthread_mutex_unlock(&(nat->lock));
}

struct sr_nat_connection *sr_nat_lookup_conn(struct sr_nat *nat, struct sr_nat_mapping *copy, 
  uint32_t ip_src, uint16_t port_src, uint32_t ip_dst, uint16_t port_dst) {
  
  pthread_mutex_lock(&(nat->lock));
  struct sr_nat_connection *con_copy = NULL;
  struct sr_nat_mapping* curr_map = nat->mappings;
  while(curr_map){
    if((curr_map->type == copy->type) && (curr_map->ip_int == copy->ip_int) && (curr_map->aux_int == copy->aux_int)){
      struct sr_nat_connection* con = curr_map->conns;
      while (con){
        if (con->ip_src == ip_src && con->port_src == port_src && con->ip_dst == ip_dst && con->port_dst == port_dst){
          con_copy = malloc(sizeof(struct sr_nat_connection));
          memcpy(con, con_copy, sizeof(struct sr_nat_connection));
          
          pthread_mutex_unlock(&(nat->lock));
          return con_copy;
        }
        con = con->next;
      }   
      break;
    }
    curr_map = curr_map->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return con_copy;
}

void sr_nat_refresh_conn(struct sr_nat *nat, struct sr_nat_mapping *copy,
  struct sr_nat_connection *con_copy) {
  pthread_mutex_lock(&(nat->lock));
  struct sr_nat_mapping* curr_map = nat->mappings;
  while(curr_map){
    if((curr_map->type == copy->type) && (curr_map->ip_int == copy->ip_int) && (curr_map->aux_int == copy->aux_int)){
      struct sr_nat_connection* con = curr_map->conns;
      while (con){
        if (con->ip_src == con_copy->ip_src && con->port_src == con_copy->port_src
            && con->ip_dst == con_copy->ip_dst && con->port_dst == con_copy->port_dst){
          con->time_wait = time(NULL);
          curr_map->time_wait = time(NULL);
          break;
        }
        con = con->next;
      }
      break;
    }
    curr_map = curr_map->next;
  }
  pthread_mutex_unlock(&(nat->lock));
}

int sr_nat_update_seq_no(struct sr_nat *nat, struct sr_nat_mapping *copy, 
  struct sr_nat_connection *con_copy, uint16_t seq_no) {
  
  pthread_mutex_lock(&(nat->lock));
  struct sr_nat_mapping* curr_map = nat->mappings;
  while(curr_map){
    if((curr_map->type == copy->type) && (curr_map->ip_int == copy->ip_int) && (curr_map->aux_int == copy->aux_int)){
      struct sr_nat_connection* con = curr_map->conns;
      while (con){
        if (con->ip_src == con_copy->ip_src && con->port_src == con_copy->port_src && con->ip_dst == con_copy->ip_dst && con->port_dst == con_copy->port_dst){
          con->seq_no = seq_no;
          pthread_mutex_unlock(&(nat->lock));
          return 1;
        }
        con = con->next;
      } 
      break;
    }
    curr_map = curr_map->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return 0;
}





