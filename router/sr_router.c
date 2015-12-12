/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_nat.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  printf("Router Accessed\n");
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  struct sr_if * iface = sr_get_interface(sr, interface);
  printf("*** -> Received packet of length %d \n",len);

  /* Ethernet Protocol */
  if(len>=34){
    uint8_t* ether_packet = malloc(len+28);
    memcpy(ether_packet,packet,len);

    uint16_t package_type = ethertype(ether_packet);
    
    if(package_type == ethertype_arp){
      /* ARP protocol */
      sr_handleARPpacket(sr, ether_packet, len, iface, interface);
    }else if(package_type == ethertype_ip){
      /* IP protocol */
      sr_handleIPpacket(sr, ether_packet,len, interface, iface);
    }else{
      /* drop package */
       printf("bad protocol! BOO! \n");
    }
    free(ether_packet);
  }
}/* end sr_ForwardPacket */

void sr_handleIPpacket(struct sr_instance* sr, uint8_t* packet,unsigned int len, char *interface, struct sr_if * iface){
  sr_ip_hdr_t * ipHeader = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
  struct sr_if *tgt_iface= sr_get_interface_from_ip(sr,ipHeader->ip_dst);

  uint16_t incm_cksum = ipHeader->ip_sum;
  ipHeader->ip_sum = 0;
  uint16_t calc_cksum = cksum((uint8_t*)ipHeader,20);
  ipHeader->ip_sum = incm_cksum;
  if (calc_cksum != incm_cksum){
      fprintf(stderr,"Bad checksum\n");
  } 
  else if (tgt_iface){
    fprintf(stderr,"For us\n");
    if(ipHeader->ip_p==6 || ipHeader->ip_p==17){ /* TCP/UDP */
      fprintf(stderr,"TCP/UDP\n");
      sr_sendICMP(sr, packet, interface, 3, 3);
    } 
    else if (ipHeader->ip_p==1 && ipHeader->ip_tos==0){ /*ICMP PING*/
      fprintf(stderr,"ICMP\n");
      sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
      incm_cksum = icmp_header->icmp_sum;
      icmp_header->icmp_sum = 0;
      calc_cksum = cksum((uint8_t*)icmp_header,len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
      icmp_header->icmp_sum = incm_cksum;
      uint8_t type = icmp_header->icmp_type;
      uint8_t code = icmp_header->icmp_code;
      if (incm_cksum != calc_cksum){
        fprintf(stderr,"Bad cksum %d != %d\n", incm_cksum, calc_cksum);
      } 
      else if (type == 8 && code == 0) {
        struct sr_rt* rt;
        rt = (struct sr_rt*)sr_find_routing_entry_int(sr, ipHeader->ip_dst);
        /*sr_sendICMP(sr, packet, interface, 0, 0);*/
        sr_sendIP(sr, packet, len, rt, interface);
      }
      else if (sr->nat && ethertype(packet)==ethertype_ip) {
        printf("handling nat\n");
        if (sr_handle_nat(sr, packet, len, interface) == 1) {
          return;
        }

      }
    }
  } 
  else if (ipHeader->ip_ttl <= 1){
    fprintf(stderr,"Packet died\n");
    sr_sendICMP(sr, packet, interface, 11, 0);
  } 
  else {
    fprintf(stderr,"Not for us\n");
    struct sr_rt* rt;
    rt = (struct sr_rt*)sr_find_routing_entry_int(sr, ipHeader->ip_dst);
    if (rt){
      if (ipHeader->ip_p==6){  /* TCP */
        if (!sr->nat){
          sr_sendICMP(sr, packet,interface,3,3);
          return;
        }
        if (tcp_cksum(sr,packet,len) == 1){
          fprintf(stderr , "** Error: TCP checksum failed \n");
          return;
        }
      }
      else {
        if (!sr->nat){
          sr_sendIP(sr, packet, len, rt, interface);
        }
        else if (sr->nat && ethertype(packet)==ethertype_ip){
          printf("handling nat\n");
          if (sr_handle_nat(sr, packet, len, interface) == 1){
            return;
          }
        }
      }
    } 
    else {
      sr_sendICMP(sr, packet, interface, 3, 0);
    }
  }
}

void sr_handleARPpacket(struct sr_instance *sr, uint8_t* packet, unsigned int len, struct sr_if * iface, const char * interface) {
    assert(packet);
    sr_ethernet_hdr_t* ethHeader = (sr_ethernet_hdr_t*) packet;
    sr_arp_hdr_t * arpHeader = (sr_arp_hdr_t *) (packet+14);

    struct sr_if *req_iface = sr_get_interface_from_ip(sr, htonl(arpHeader->ar_tip));

    /* handle an arp request.*/
    if (ntohs(arpHeader->ar_op) == arp_op_request) {
        /* found an ip->mac mapping. send a reply to the requester's MAC addr */
        if (req_iface){
          arpHeader->ar_op = ntohs(arp_op_reply);
          uint32_t temp = arpHeader->ar_sip;
          arpHeader->ar_sip = arpHeader->ar_tip;
          arpHeader->ar_tip = temp;
          memcpy(arpHeader->ar_tha, arpHeader->ar_sha,6);
          memcpy(arpHeader->ar_sha, iface->addr,6);

          /*swapping outgoing and incoming addr*/
          set_eth_addr(ethHeader, iface->addr, ethHeader->ether_shost);
          sr_send_packet(sr,(uint8_t*)ethHeader,len,iface->name);
        }
    }
    /* handle an arp reply */
    else if (ntohs(arpHeader->ar_op) == arp_op_reply) {
      struct sr_packet *req_packet = NULL;
      struct sr_arpreq *req = NULL;
      pthread_mutex_lock(&(sr->cache.lock));
      req = sr_arpcache_insert(&(sr->cache), arpHeader->ar_sha, arpHeader->ar_sip);
      if(req){
          fprintf(stderr,"Clearing queue\n");
          for (req_packet = req->packets; req_packet != NULL; req_packet = req_packet->next){
              sr_ethernet_hdr_t * outETH = (sr_ethernet_hdr_t *)(req_packet->buf);
              memcpy(outETH->ether_shost, req_iface->addr,6);
              memcpy(outETH->ether_dhost, arpHeader->ar_sha,6);
              sr_ip_hdr_t * outIP = (sr_ip_hdr_t *)(req_packet->buf+14);
              outIP->ip_ttl = outIP->ip_ttl-1;
              outIP->ip_sum = 0;
              outIP->ip_sum = cksum((uint8_t *)outIP,20);
              sr_send_packet(sr,req_packet->buf,req_packet->len,req_iface->name);
          }
          sr_arpreq_destroy(&(sr->cache), req);
      }
      pthread_mutex_unlock(&(sr->cache.lock));
    }
}

void sr_sendIP(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_rt *rt, char *interface) {
  struct sr_if* iface = sr_get_interface(sr, rt->interface);
  
  pthread_mutex_lock(&(sr->cache.lock));
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, (uint32_t)(rt->gw.s_addr));
  sr_ethernet_hdr_t *ethHeader = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ipHeader = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    
  if (entry) {
    iface = sr_get_interface(sr, rt->interface);
    set_eth_addr(ethHeader, iface->addr, entry->mac);
    ipHeader->ip_ttl = ipHeader->ip_ttl - 1;
    ipHeader->ip_sum = 0;
    ipHeader->ip_sum = cksum((uint8_t *)ipHeader, sizeof(sr_ip_hdr_t));
    sr_send_packet(sr, packet, len, rt->interface);
    free(entry);
  } 
  else {
    memcpy(ethHeader->ether_shost, iface->addr, 6);
    /*struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), (uint32_t)(rt->gw.s_addr), packet, 
                                                 len, rt->interface); */
    handle_arpreq(sr,req);
  }
  pthread_mutex_unlock(&(sr->cache.lock));
}

void sr_sendICMP(struct sr_instance *sr, uint8_t *packet, const char* iface, uint8_t type, uint8_t code) {
   sr_ethernet_hdr_t *ethHeader = (sr_ethernet_hdr_t *)(packet);  
    sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  
    int len;
    if(type == 3 || type == 11){
      len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
    }else{
      len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr);
    }
    uint8_t* newPacket = calloc(1, len);

    sr_ethernet_hdr_t *ethPacket = (sr_ethernet_hdr_t *)(newPacket);
    sr_ip_hdr_t *ipPacket = (sr_ip_hdr_t *)(newPacket + sizeof(struct sr_ethernet_hdr));

    memcpy(ethPacket, ethHeader, sizeof(sr_ethernet_hdr_t));
    memcpy(ipPacket, ipHeader, sizeof(sr_ip_hdr_t));

    struct sr_if* interface = sr_get_interface(sr,iface);
    int addr_i;
    for (addr_i=0;addr_i<ETHER_ADDR_LEN;addr_i++){
      ethPacket->ether_dhost[addr_i] = ethPacket->ether_shost[addr_i]; 
      ethPacket->ether_shost[addr_i] = interface->addr[addr_i];
    }
    ethPacket->ether_type = ntohs(ethertype_ip);
 
    /*ipPacket->ip_len = sizeof(sr_ip_hdr_t);*/
    ipPacket->ip_p = ip_protocol_icmp;
    ipPacket->ip_hl = 5;
    ipPacket->ip_id = ipPacket->ip_id;
    ipPacket->ip_len = htons(len-sizeof(sr_ethernet_hdr_t)); /*THE BANE OF MY EXISTANCE*/
    ipPacket->ip_ttl = 65;

    uint32_t temp_dst = ipPacket->ip_dst;
    ipPacket->ip_dst=ipPacket->ip_src;
    ipPacket->ip_src=temp_dst;
    ipPacket->ip_ttl--;
    ipPacket->ip_sum = 0;

    ipPacket->ip_src = interface->ip;
    ipPacket->ip_sum = cksum(ipPacket,sizeof(sr_ip_hdr_t));

    if(type == 3 || type == 11){
      sr_icmp_t3_hdr_t *icmpPacket = (sr_icmp_t3_hdr_t *)(newPacket + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
      memcpy(icmpPacket->data, ipHeader, sizeof(sr_ip_hdr_t)+8);
      icmpPacket->icmp_type = type;
      icmpPacket->icmp_code = code;
      icmpPacket->unused = 0;
      icmpPacket->next_mtu = 0;
      icmpPacket->icmp_sum = 0;
      icmpPacket->icmp_sum = cksum(icmpPacket, sizeof(struct sr_icmp_t3_hdr));
    }else{
      sr_icmp_hdr_t *icmpPacket = (sr_icmp_hdr_t *)(newPacket + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
      icmpPacket->icmp_type = type;
      icmpPacket->icmp_code = code;
      icmpPacket->icmp_sum = 0;
      icmpPacket->icmp_sum = cksum(icmpPacket, sizeof(struct sr_icmp_hdr));
    }

    print_hdrs(newPacket, len);
    sr_send_packet(sr, newPacket, len, iface);
}

int sr_handle_nat(struct sr_instance* sr /* borrowed */,
                  uint8_t* packet /* borrowed */ ,
                  unsigned int len,
                  const char* iface /* borrowed */)
{
  if(sr->nat == NULL){
    return 0;
  }
  print_hdr_ip(packet+ sizeof(struct sr_ethernet_hdr));
  sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));

  struct sr_nat_mapping *mapping;
  if(strcmp(iface,"eth1")==0){
    Debug("Internal packet\n");
    uint16_t aux_int;
    sr_icmp_echo_hdr_t *icmpHeader;
    sr_tcp_hdr_t *tcpHeader;

    /*Internal mapping lookup and packet translating*/
    sr_nat_mapping_type type;
    
    if (ipHeader->ip_p == ip_protocol_icmp){
      Debug("ICMP Packet\n");
      type = nat_mapping_icmp;
      icmpHeader = (sr_icmp_echo_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
      aux_int = ntohs(icmpHeader->icmp_id);
      mapping = sr_nat_lookup_internal(sr->nat,ntohl(ipHeader->ip_src),aux_int,type);
    }
    else if (ipHeader->ip_p == ip_protocol_tcp){
      Debug("TCP Packet\n");
      type = nat_mapping_tcp;
      tcpHeader = (sr_tcp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
      aux_int=ntohs(tcpHeader->source);
      mapping = sr_nat_lookup_internal(sr->nat,ipHeader->ip_src,aux_int,type);
    }
    
    if (mapping == NULL){
      Debug("No mapping available, making new one\n");
      mapping = sr_nat_insert_mapping(sr->nat,ipHeader->ip_src,aux_int,type);
    }
    Debug("Applying map\n");
    print_addr_ip_int(mapping->ip_ext);
    print_addr_ip_int(mapping->ip_int);
    ipHeader->ip_src=mapping->ip_ext;

    if (ipHeader->ip_p == ip_protocol_icmp){
      icmpHeader->icmp_id=htons(mapping->aux_ext);
      icmpHeader->icmp_sum=0;
      icmpHeader->icmp_sum = cksum(icmpHeader,sizeof(sr_icmp_echo_hdr_t));
    }
    else if (ipHeader->ip_p == ip_protocol_tcp){
      tcpHeader->source=ntohs(mapping->aux_ext);
      tcp_cksum(sr,packet,len);
      if (sr_nat_handle_internal_conn(sr->nat,mapping,packet,len) ==1){
        Debug("Something went wrong, dropping packet\n");
        free(mapping);
        return 1;
      }
    }
  }
  else{
    Debug("External packet\n");
    uint16_t aux_ext;
    sr_icmp_echo_hdr_t *icmpHeader;
    sr_tcp_hdr_t *tcpHeader;
    sr_nat_mapping_type type;

    /*Internal mapping lookup and packet translating*/
    if (ipHeader->ip_p == ip_protocol_icmp){
      Debug("ICMP Packet\n");
      type = nat_mapping_icmp;
      icmpHeader = (sr_icmp_echo_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
      aux_ext = ntohs(icmpHeader->icmp_id);
      Debug("%d\n",aux_ext);
      mapping = sr_nat_lookup_external(sr->nat,aux_ext,type);
    }
    else if (ipHeader->ip_p == ip_protocol_tcp){
      Debug("TCP Packet\n");
      type = nat_mapping_tcp;
      tcpHeader = (sr_tcp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
      mapping = sr_nat_lookup_external(sr->nat,ntohs(tcpHeader->destination),type);
    }

    if (mapping == NULL){
      if (ipHeader->ip_p == ip_protocol_tcp){
        Debug("Making wildcard mapping to handle unsolicited syns\n");
        mapping = sr_nat_insert_mapping_unsol(sr->nat,ntohs(tcpHeader->destination),type);
        if (sr_nat_handle_external_conn(sr->nat,mapping,packet,len) ==1){
          Debug("Unsolicited syn, don't send\n");
          return 1;
        }
      }else{
        Debug("No mapping available, welp\n");
        free(mapping);
        return 1;
      }
    }
    else{
      Debug("Mapping found, applying map\n");
      ipHeader->ip_dst=mapping->ip_int;

      if (ipHeader->ip_p == ip_protocol_icmp){
        icmpHeader->icmp_id=ntohs(mapping->aux_int);
        icmpHeader->icmp_sum=0;
        icmpHeader->icmp_sum = cksum(icmpHeader,sizeof(sr_icmp_echo_hdr_t));
      }
      else if (ipHeader->ip_p == ip_protocol_tcp){
        tcpHeader->destination=ntohs(mapping->aux_int);
        tcp_cksum(sr,packet,len);
      
        if (sr_nat_handle_external_conn(sr->nat,mapping,packet,len) ==1){
          Debug("Unsolicited syn, don't send\n");
          return 1;
        }
      }
    }           
  }
  ipHeader->ip_sum=0;
  ipHeader->ip_sum = cksum(ipHeader,sizeof(sr_ip_hdr_t));
  if (mapping != NULL)
    free(mapping);
  return 0;
}

int tcp_cksum(struct sr_instance* sr, uint8_t* packet, unsigned int len){
  
  assert(sr);
  assert(packet);

  sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  sr_tcp_hdr_t *tcpHeader = (sr_tcp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));

  sr_tcp_pshdr_t *tcp_pshdr = calloc(1,sizeof(struct sr_tcp_pshdr));
  tcp_pshdr->ip_src = ipHeader->ip_src;
  tcp_pshdr->ip_dst = ipHeader->ip_dst;
  tcp_pshdr->ip_p = ipHeader->ip_p;
  uint16_t tcp_length = len-sizeof(struct sr_ethernet_hdr)-sizeof(struct sr_ip_hdr);
  tcp_pshdr->len = htons(tcp_length);

  uint16_t checksum = tcpHeader->checksum;
  tcpHeader->checksum = 0; 

  uint8_t *total_tcp = calloc(1, sizeof(struct sr_tcp_pshdr)+tcp_length);
  memcpy(total_tcp,tcp_pshdr, sizeof(struct sr_tcp_pshdr));
  memcpy((total_tcp+sizeof(struct sr_tcp_pshdr)), tcpHeader, tcp_length);

  Debug("TCP Checksum: %d \n",cksum(total_tcp, sizeof(struct sr_tcp_pshdr)+tcp_length)); 
  uint16_t new_cksum = cksum(total_tcp, sizeof(struct sr_tcp_pshdr)+tcp_length);
  if (checksum != new_cksum) {
      tcpHeader->checksum = new_cksum;
      free(tcp_pshdr);
      free(total_tcp);
      return 1;
  }
  tcpHeader->checksum = new_cksum;
  free(tcp_pshdr);
  free(total_tcp);
  return 0;
}