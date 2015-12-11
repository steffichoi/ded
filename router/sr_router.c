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

void sr_init(struct sr_instance* sr, int nat_usage) {
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
      sr_handleARPpacket(sr, ether_packet, len, iface);
    }else if(package_type == ethertype_ip){
      /* IP protocol */
      sr_handleIPpacket(sr, ether_packet,len, interface);
    }else{
      /* drop package */
       printf("bad protocol! BOO! \n");
    }
    free(ether_packet);
  }
}/* end sr_ForwardPacket */

void sr_handleIPpacket(struct sr_instance* sr, uint8_t* packet,unsigned int len, char *interface){
  sr_ip_hdr_t * ipHeader = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
  struct sr_if *next_iface= sr_get_interface_from_ip(sr,ipHeader->ip_dst);

  uint16_t incm_cksum = ipHeader->ip_sum;
  ipHeader->ip_sum = 0;
  if (incm_cksum != cksum(ipHeader, sizeof(sr_ip_hdr_t))) {
    fprintf(stderr, "Error: IP checksum failed \n");
    return;
  }
  else if (ipHeader->ip_src == 0) {
    return;
  }
  ipHeader->ip_sum = incm_cksum;

  if (next_iface){
    if(ipHeader->ip_p==6){ /*TCP*/
        sr_sendICMP(sr, packet, interface, 3, 3);
    } 
    else if (ipHeader->ip_p==17){ /*UDP*/
      sr_sendICMP(sr, packet, interface, 3, 3);
    } 
    else if (ipHeader->ip_p==1 && ipHeader->ip_tos==0){ /*ICMP PING*/
      sr_icmp_hdr_t* icmpHeader = (sr_icmp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
      incm_cksum = icmpHeader->icmp_sum;
      icmpHeader->icmp_sum = 0;
      icmpHeader->icmp_sum = incm_cksum;
      if (icmpHeader->icmp_type == 8 && icmpHeader->icmp_code == 0) {
          sr_sendICMP(sr, packet, interface, 0, 0);
      }
    }
  } 
  else if (ipHeader->ip_ttl == 0){   /* ttl ded */
      sr_sendICMP(sr, packet, interface, 11, 0);
  }
  else {
      struct sr_rt* rt;
      rt = (struct sr_rt*)sr_find_routing_entry_int(sr, ipHeader->ip_dst);
      if (rt){
          sr_sendIP(sr,packet,len,rt);
      } else {
          sr_sendICMP(sr, packet, interface, 3, 0);
      }
  }
}

void sr_handleARPpacket(struct sr_instance *sr, uint8_t* packet, unsigned int len, struct sr_if * iface) {
    assert(packet);
    sr_ethernet_hdr_t* ethHeader = (sr_ethernet_hdr_t*) packet;
    sr_arp_hdr_t * arpHeader = (sr_arp_hdr_t *) (packet+14);

    enum sr_arp_opcode request = arp_op_request;
    enum sr_arp_opcode reply = arp_op_reply;

    struct sr_if *interface = sr_get_interface_from_ip(sr, htonl(arpHeader->ar_tip));

    /* handle an arp request.*/
    if (ntohs(arpHeader->ar_op) == request) {
        /* found an ip->mac mapping. send a reply to the requester's MAC addr */
        if (interface){
          arpHeader->ar_op = ntohs(reply);
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
    else {
      struct sr_packet *req_packet = NULL;
      struct sr_arpreq *req = NULL;
      pthread_mutex_lock(&(sr->cache.lock));

      for (req = sr->cache.requests; req != NULL; req = req->next){
        if(req->ip == arpHeader->ar_sip){
          /* find the interface the packets should be sent out of */
          struct sr_rt * rt = (struct sr_rt *)sr_find_routing_entry_int(sr, req->ip);
          if (rt) {
            iface = sr_get_interface(sr, rt->interface);
            /* send all packets waiting on the request that was replied to */
            for (req_packet = req->packets; req_packet != NULL; req_packet = req_packet->next) {
              sr_ethernet_hdr_t * outEther = (sr_ethernet_hdr_t *)req_packet->buf;
              memcpy(outEther->ether_shost, iface->addr,6);
              memcpy(outEther->ether_dhost, ethHeader->ether_shost,6);

              sr_ip_hdr_t * outIP = (sr_ip_hdr_t *)(req_packet->buf+14);
              outIP->ip_ttl = outIP->ip_ttl-1;
              outIP->ip_sum = 0;
              outIP->ip_sum = cksum((uint8_t *)outIP,20);

              sr_send_packet(sr,req_packet->buf,req_packet->len,iface->name);
            }
            sr_arpreq_destroy(&(sr->cache), req);
          }
          break;
        }
      }
      pthread_mutex_unlock(&(sr->cache.lock));
      sr_arpcache_insert(&(sr->cache),arpHeader->ar_sha,arpHeader->ar_sip);
    }
}

void sr_sendIP(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_rt *rt) {
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
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), (uint32_t)(rt->gw.s_addr), packet, 
                                                 len, rt->interface);
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





