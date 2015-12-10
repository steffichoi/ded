
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