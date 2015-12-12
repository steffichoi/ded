
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

int sr_nat_init(struct sr_instance *sr, uint32_t icmp_to, uint32_t tcp_establish_to, uint32_t tcp_transitory_to) { /* Initializes the nat */
  assert(sr);
  struct sr_nat *nat = sr->nat;
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
  nat->next_ext_port = MIN_PORT;
  nat->icmp_to=icmp_to;
  nat->tcp_establish_to=tcp_establish_to;
  nat->tcp_transitory_to=tcp_transitory_to;
  /* Initialize any variables here */
  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));
  assert(nat);

  /* free nat memory here */
  if (nat) {
    struct sr_nat_mapping *curr_map = nat->mappings;
    struct sr_nat_mapping *free_map;
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
  free(&(nat->ip_ext));
  free(&(nat->icmp_to));
  free(&(nat->tcp_establish_to));
  free(&(nat->tcp_transitory_to));

  }
  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
  pthread_mutexattr_destroy(&(nat->attr));
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = nat_ptr;
  while (1) {
    sleep(1.0);
    
    /* pthread_mutex_lock(&(nat->lock)); */
    time_t curtime = time(NULL);
    /*Debug("NAT Tick Tock\n");*/
    /* handle periodic tasks here */
    struct sr_nat_mapping *curr_map = nat->mappings;
    /*Debug("Cur Mapping %d\n",curr_map);*/
    struct sr_nat_mapping *prev_map = NULL;
    for(;curr_map != NULL; curr_map = curr_map->next){
      int time_passed = difftime(curtime,curr_map->time_wait);
/*      Debug("Mapping time passed %d\n",time_passed);*/
      if (curr_map->type == nat_mapping_icmp && time_passed>=nat->icmp_to){
        Debug("Deleting ICMP mapping\n");
        sr_nat_delete_mapping(nat,curr_map,prev_map);
      }
      else if (curr_map->type == nat_mapping_tcp){
        if (curr_map->conns == NULL){
          Debug("Cleanup of TCP mapping\n");
          sr_nat_delete_mapping(nat,curr_map,prev_map);
        }else{
          struct sr_nat_connection *curr_conn = curr_map->conns;
          struct sr_nat_connection *prev_conn = NULL;
          for(;curr_conn!=NULL;curr_conn=curr_conn->next){
            int conn_time_passed = difftime(curtime,curr_conn->time_wait);
            if(conn_time_passed>=nat->tcp_establish_to && curr_conn->state == nat_conn_est){
              Debug("Deleting established TCP connection\n");
              sr_nat_delete_connection(curr_map,curr_conn,prev_conn);
            }else if (time_passed>=nat->tcp_transitory_to && curr_conn->state != nat_conn_est && curr_conn->state != nat_conn_unest){
              Debug("Deleting transitory TCP connection\n");
              sr_nat_delete_connection(curr_map,curr_conn,prev_conn);
            }else if(conn_time_passed>=6 && curr_conn->packet != NULL){
              Debug("Deleting unsolicited SYN TCP connection\n");
              /*uint8_t *packet = curr_conn->packet;*/
              sr_sendICMP(sr, curr_conn->packet, "eth2", 3, 3);
              free(curr_conn->packet);
              sr_nat_delete_connection(curr_map,curr_conn,prev_conn);
            }
            else {
              prev_conn = curr_conn;
            }
          }
        }
      }
      else
        prev_map = curr_map;
    }
    /*pthread_mutex_unlock(&(nat->lock));*/
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
  uint16_t aux_ext;
  if (type != nat_mapping_icmp){
    aux_ext = nat->next_ext_port;
    bool found_port = false;
    uint16_t port = nat->next_ext_port+1;
    struct sr_nat_mapping *mappings;
    for(;!found_port;port++){
      found_port=true;
      if (port > MAX_PORT){
        port=MIN_PORT;
      }
      mappings = nat->mappings;
      for(;mappings!=NULL;mappings=mappings->next){
        if(mappings->aux_ext==port){
          found_port=false;
        }
      }
    }
    nat->next_ext_port = port;

  }
  /*
  else{
    aux_ext = nrand16(1);
  } */
  /*Set values*/
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->ip_ext = nat->ip_ext;
  mapping->aux_int = aux_int;
  mapping->aux_ext = aux_ext;
  mapping->time_wait = time(NULL);
  mapping->next=NULL;
  mapping->conns = NULL; 

  /*Add to mappings*/
  struct sr_nat_mapping *map_list = nat->mappings;
  if (map_list != NULL){
    while(map_list->next != NULL) {
      map_list=map_list->next;
    }
    map_list->next=mapping;
  }
  else{
    nat->mappings = mapping;
  }

  struct sr_nat_mapping *copy = (struct sr_nat_mapping *) malloc(sizeof (struct sr_nat_mapping));
  memcpy(copy,mapping,sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

struct sr_nat_mapping *sr_nat_insert_mapping_unsol(struct sr_nat *nat,
  uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  uint32_t ip_int = htonl(0);
  uint16_t aux_int= htons(1);
  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = (struct sr_nat_mapping *) malloc(sizeof (struct sr_nat_mapping));

  Debug("%d\n",aux_ext);
    
  /*Sets values*/
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->ip_ext = nat->ip_ext;
  mapping->aux_int = aux_int;
  mapping->aux_ext = aux_ext;
  mapping->time_wait = time(NULL);
  mapping->next=NULL;

  mapping->conns = NULL; 

  /*Adds to mappings*/
  struct sr_nat_mapping *map_list = nat->mappings;
  if (map_list != NULL){
    while(map_list->next != NULL)
      map_list=map_list->next;

    map_list->next=mapping;
  }
  else{
    nat->mappings = mapping;
  }

  /*Generates copy and returns it*/
  struct sr_nat_mapping *copy = (struct sr_nat_mapping *) malloc(sizeof (struct sr_nat_mapping));
  memcpy(copy,mapping,sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

void sr_nat_refresh_mapping(struct sr_nat *nat, struct sr_nat_mapping *copy){
  pthread_mutex_lock(&(nat->lock));
  struct sr_nat_mapping* curr_map = nat->mappings;
  while(curr_map){
    if((curr_map->type == copy->type) && (curr_map->ip_int == copy->ip_int) && (curr_map->aux_int == copy->aux_int)){
      curr_map->time_wait = time(NULL);
      break;
    }
    curr_map = curr_map->next;
  }
  pthread_mutex_unlock(&(nat->lock));
}

void sr_nat_delete_mapping(struct sr_nat *nat, struct sr_nat_mapping *del_map,
  struct sr_nat_mapping *prev){

  assert(del_map);

  if(prev == NULL){
    nat->mappings = del_map->next;
  }
  else{
    prev->next = del_map->next;
  }
  free(del_map);
}

void sr_nat_ext_ip(struct sr_nat *nat,struct sr_instance* sr)
{
    pthread_mutex_lock(&(nat->lock));
    nat->ip_ext = sr_get_interface(sr,"eth2")->ip;
/*    Debug("Ext IP set to ");
    print_addr_ip_int(nat->ip_ext);*/
    pthread_mutex_unlock(&(nat->lock));
}

/* tcp functions! */
void sr_nat_delete_connection(struct sr_nat_mapping *map, struct sr_nat_connection *del_conn,
  struct sr_nat_connection *prev){

  assert(del_conn);

  if(prev == NULL){
    map->conns = del_conn->next;
  }else{
    prev->next = del_conn->next;
  }
  free(del_conn);
}

int sr_nat_handle_external_conn(struct sr_nat *nat,
  struct sr_nat_mapping *copy,
  uint8_t* packet /* borrowed */,
  unsigned int len) {

  assert(nat);
  assert(copy);
  assert(packet);

  sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(ipHeader->ip_p == ip_protocol_tcp);
  sr_tcp_hdr_t *tcpHeader = (sr_tcp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *mapping = nat->mappings;
  for(;mapping != NULL; mapping = mapping->next){
    if (mapping->ip_int == copy->ip_int
      && mapping->aux_int == copy->aux_int)
      break;
  }
  assert(mapping);

  uint32_t ip_dst = ntohs(ipHeader->ip_src);
  uint16_t port_dst = ntohs(tcpHeader->source);

  Debug("Connection lookup\n");
  struct sr_nat_connection *conn = mapping->conns;
  struct sr_nat_connection *prev_conn = NULL;
  for(;conn != NULL; conn = conn->next){
    if (conn->ip_dst == ip_dst && conn->port_dst == port_dst)
      break;
    prev_conn = conn;
  }
  /*Connection doesn't exist*/
  if (conn == NULL){
    if(tcpHeader->flags != tcp_flag_syn){
      Debug("Huh? This isn't a syn packet\n");
      pthread_mutex_unlock(&(nat->lock));
      return 1;
    }
    Debug("No current connection, making unsolicited syn conn\n");
    conn = malloc(sizeof(struct sr_nat_connection));
    conn->ip_dst=ip_dst;
    conn->port_dst=port_dst;
    conn->state=nat_conn_unest;
    conn->last_state = false;
    uint8_t* unsol_pac = malloc(len);
    memcpy(unsol_pac,packet,len);
    conn->packet= unsol_pac;
    conn->next=NULL;

    /*Adds to connections*/
    struct sr_nat_connection *conn_list = mapping->conns;
    if (conn_list != NULL){
      while(conn_list->next != NULL)
        conn_list=conn_list->next;

      conn_list->next = conn;
    }
    else{
      mapping->conns = conn;
    }
  }

  /*Do state operations on the connection*/
  switch (conn->state)
  {

    /*Do nothing here*/
    case nat_conn_unest:
      if (conn->last_state)
        Debug("Got here somehow?\n");
      else{
        Debug("Holding on to packet\n");
          conn->time_wait = time(NULL);
          pthread_mutex_unlock(&(nat->lock));
          return 1;
      }
      break;

    /*Look for syn+ack*/  
    case nat_conn_syn:
      if (tcpHeader->flags == tcp_flag_syn+tcp_flag_ack
        && conn->last_state){
        Debug("Syn Ack recieved\n");
        conn->state=nat_conn_synack;
        conn->last_state = false;
      }else if (tcpHeader->flags == tcp_flag_syn+tcp_flag_ack
        && conn->last_state){
        Debug("Second syn, drop it\n");
        conn->last_state = false;
        pthread_mutex_unlock(&(nat->lock));
        return 1;
      }
      break;

    /*Look for ack to establish connection*/
    case nat_conn_synack:
      if (tcpHeader->flags == tcp_flag_ack
        && conn->last_state){
        Debug("Connection established\n");
        conn->state=nat_conn_est;
        conn->last_state = false;
      }
      break;

    /*Look for fin*/
    case nat_conn_est:
      if (tcpHeader->flags == tcp_flag_fin){
        Debug("Fin1 recieved\n");
        conn->state=nat_conn_fin1;
        conn->last_state = false;
      }
      break;

    /*Look for ack or fin+ack*/
    case nat_conn_fin1:
      if (tcpHeader->flags == tcp_flag_fin
        && conn->last_state){
        Debug("Ack recieved\n");
        conn->state=nat_conn_fin1ack;
        conn->last_state = false;
      }
      else if (tcpHeader->flags == tcp_flag_fin+tcp_flag_ack
        && conn->last_state){
        Debug("Fin Ack recieved\n");
        conn->state=nat_conn_fin2;
        conn->last_state = false;
      }
      break;

    /*Look for fin again*/
    case nat_conn_fin1ack:
      if (tcpHeader->flags == tcp_flag_fin
        && conn->last_state){
        Debug("Fin2 recieved\n");
        conn->state=nat_conn_fin1ack;
        conn->last_state = false;
      }
      break;

    /*Look for ack to fully close connection*/
    case nat_conn_fin2:
      if (tcpHeader->flags == tcp_flag_ack
        && conn->last_state){
        Debug("Closing connection\n");
        sr_nat_delete_connection(mapping,conn,prev_conn);
        pthread_mutex_unlock(&(nat->lock));
        return 0;
      }
      break;
  }
  conn->time_wait=time(NULL);
  pthread_mutex_unlock(&(nat->lock));
  return 0;
}
int sr_nat_handle_internal_conn(struct sr_nat *nat,
  struct sr_nat_mapping *copy,  
  uint8_t* packet /* borrowed */,
  unsigned int len) {

  assert(nat);
  assert(copy);
  assert(packet);

  sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  assert(ipHeader->ip_p == ip_protocol_tcp);
  sr_tcp_hdr_t *tcpHeader = (sr_tcp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *mapping = nat->mappings;
  for(;mapping != NULL; mapping = mapping->next){
    if (mapping->ip_int == copy->ip_int
      && mapping->aux_int == copy->aux_int)
      break;
  }
  assert(mapping);

  uint32_t ip_dst = ntohs(ipHeader->ip_dst);
  uint16_t port_dst = ntohs(tcpHeader->destination);

  Debug("Connection lookup\n");
  struct sr_nat_connection *conn = mapping->conns;
  struct sr_nat_connection *prev_conn = NULL;
  for(;conn != NULL; conn = conn->next){
    if (conn->ip_dst == ip_dst && conn->port_dst == port_dst)
      break;
    prev_conn = conn;
  }
  /*Connection doesn't exist*/
  if (conn == NULL){
    if(tcpHeader->flags != tcp_flag_syn){
      Debug("New connection, but this isn't a syn packet\n");
      pthread_mutex_unlock(&(nat->lock));
      return 1;
    }
    Debug("No current connection, making new one\n");
    conn = malloc(sizeof(struct sr_nat_connection));
    conn->ip_dst=ip_dst;
    conn->port_dst=port_dst;
    conn->state=nat_conn_syn;
    conn->last_state = true;
    conn->packet = NULL;
    conn->next = NULL;

    /*Adds to connections*/
    struct sr_nat_connection *conn_list = mapping->conns;
    if (conn_list != NULL){
      while(conn_list->next != NULL)
        conn_list = conn_list->next;

      conn_list->next = conn;
    }
    else{
      mapping->conns = conn;
    }
  }

  /*Do state operations on the connection*/
  switch (conn->state)
  {
    /*For waiting unsolicited syns*/
    case nat_conn_unest:
      if (tcpHeader->flags == tcp_flag_syn
        && !conn->last_state){
        Debug("Dropping unsolicited syn\n");
        conn->state=nat_conn_syn;
        conn->last_state=true;
        free(conn->packet);
      }
      break;

    /*Look for syn+ack*/  
    case nat_conn_syn:
      if (tcpHeader->flags == tcp_flag_syn+tcp_flag_ack
        && !conn->last_state){
        Debug("Syn Ack recieved\n");
        conn->state=nat_conn_synack;
        conn->last_state = true;
      }else if (tcpHeader->flags == tcp_flag_syn+tcp_flag_ack
        && !conn->last_state){
        Debug("Second syn, drop it\n");
        conn->last_state = true;
        pthread_mutex_unlock(&(nat->lock));
        return 1;
      }
      break;

    /*Look for ack to establish connection*/
    case nat_conn_synack:
      if (tcpHeader->flags == tcp_flag_ack
        && !conn->last_state){
        Debug("Connection established\n");
        conn->state=nat_conn_est;
        conn->last_state = true;
      }
      break;

    /*Look for fin*/
    case nat_conn_est:
      if (tcpHeader->flags == tcp_flag_fin){
        Debug("Fin1 recieved\n");
        conn->state=nat_conn_fin1;
        conn->last_state = true;
      }
      break;

    /*Look for ack or fin+ack*/
    case nat_conn_fin1:
      if (tcpHeader->flags == tcp_flag_fin
        && !conn->last_state){
        Debug("Ack recieved\n");
        conn->state=nat_conn_fin1ack;
        conn->last_state = true;
      }
      else if (tcpHeader->flags == tcp_flag_fin+tcp_flag_ack
        && !conn->last_state){
        Debug("Fin Ack recieved\n");
        conn->state=nat_conn_fin2;
        conn->last_state = true;
      }
      break;

    /*Look for fin again*/
    case nat_conn_fin1ack:
      if (tcpHeader->flags == tcp_flag_fin
        && !conn->last_state){
        Debug("Fin2 recieved\n");
        conn->state=nat_conn_fin1ack;
        conn->last_state = true;
      }
      break;

    /*Look for ack to fully close connection*/
    case nat_conn_fin2:
      if (tcpHeader->flags == tcp_flag_ack
        && !conn->last_state){
        Debug("Closing connection\n");
        sr_nat_delete_connection(mapping,conn,prev_conn);
        pthread_mutex_unlock(&(nat->lock));
        return 0;
      }
      break;
  }
  conn->time_wait=time(NULL);
  pthread_mutex_unlock(&(nat->lock));
  return 0;
}