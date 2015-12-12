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
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t checksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0; 
  Debug("IP Checksum: %d \n",cksum(ip_hdr,sizeof(sr_ip_hdr_t))); 
  if (checksum != cksum(ip_hdr,sizeof(sr_ip_hdr_t))) {
      fprintf(stderr , "** Error: IP checksum failed \n");
      return;
  }else if (ip_hdr->ip_src == 0){
    return;
  }
  ip_hdr->ip_sum = checksum;

  uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
  
  /*Creates reverse packet*/
  sr_ip_hdr_t *ip_ret = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
  
  uint32_t temp_dst = ip_ret->ip_dst;
  ip_ret->ip_dst=ip_hdr->ip_src;
  ip_ret->ip_src=temp_dst;
  ip_ret->ip_ttl--;
  ip_ret->ip_sum = 0;

  /*Packet is too old, time to die*/
  if(ip_ret->ip_ttl == 0){
    Debug("Packet is too old, time to die");
    sr_sendICMP(sr,packet,interface,11,0);
  }/*The packet is for someone else*/
  else if (!sr_get_interface_from_ip(sr,ip_hdr->ip_dst) ||
   (sr->nat != NULL && interface[3]=='2')){
      Debug("Not meant for me, re-route\n");
      if (!sr_get_interface_from_ip(sr,ip_ret->ip_src) &&
        !(sr->nat != NULL && interface[3]=='2')){
        Debug("No route for packet, send ICMP back\n");
        sr_sendICMP(sr, packet,interface,3,0);
        return;
      }
      else if (ip_proto != ip_protocol_icmp){
        if (ip_proto == ip_protocol_tcp){
          if (sr->nat == NULL){
            sr_sendICMP(sr, packet,interface,3,3);
            return;
          }
          if (tcp_cksum(sr,packet,len) == 1){
            fprintf(stderr , "** Error: TCP checksum failed \n");
            return;
          }
        }
      }
      reroute_packet(sr,packet,len,interface);
      return;
  }
  else if (ip_proto == ip_protocol_icmp) { /* ICMP */
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    checksum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    Debug("ICMP Checksum: %d \n",cksum(icmp_hdr,64)); 
    if (checksum != cksum(icmp_hdr,64)) {
      fprintf(stderr , "** Error: ICMP checksum failed \n");
    }else if (sr->nat != NULL){
      reroute_packet(sr,packet,len,interface);
    }
    else{
      sr_icmp_hdr_t *icmp_ret = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      icmp_ret->icmp_sum = 0;
      if (icmp_hdr->icmp_type == 8){
        Debug("ICMP Echo Request\n");
        icmp_ret->icmp_type = 0;
        ip_ret->ip_sum = cksum(ip_ret,sizeof(sr_ip_hdr_t));
        icmp_ret->icmp_sum = cksum(icmp_ret,64);
        print_hdrs(packet,len);
        sr_send_packet(sr,packet,len,interface); 
      }
      else{
        fprintf(stderr, "Unsupported ICMP Message: Type %d Code %d\n",icmp_hdr->icmp_type,icmp_hdr->icmp_code);
      }
    }
  }
  else{
    Debug("Returns ICMP Port Unreachable\n");
    sr_sendICMP(sr,packet,interface,3,3);
  }
}

void sr_handleARPpacket(struct sr_instance *sr, uint8_t* packet, unsigned int len, struct sr_if * iface, const char * interface) {
  sr_arp_hdr_t* a_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t *)(packet);    
  sr_ethernet_hdr_t *e_ret = (sr_ethernet_hdr_t *)(ret_pac); 

  uint8_t *ret_pac = malloc(len);
  memcpy(ret_pac,packet,len);
  
  struct sr_if* if_i = sr_get_interface(sr,iface);
  assert(if_i);
  int addr_i;
  for (addr_i=0;addr_i<ETHER_ADDR_LEN;addr_i++){
    e_ret->ether_dhost[addr_i] = e_hdr->ether_shost[addr_i]; 
    e_ret->ether_shost[addr_i] = if_i->addr[addr_i];
  }

  if(ntohs(a_hdr->ar_op) == 2){
    Debug("This is a reply\n");
    if (sr_get_interface_from_ip(sr,a_hdr->ar_tip)){
      Debug("Mine, trying to cache\n");
      struct sr_arpreq* req;
      
      if((req= sr_arpcache_insert(&sr->cache,a_hdr->ar_sha,a_hdr->ar_sip)) != NULL){
        struct sr_packet* reply_pac = req->packets;
        Debug("Request cached, releasing packets\n");
        for (;reply_pac != NULL; reply_pac=reply_pac->next){

          struct sr_if* if_list = sr_get_interface(sr,reply_pac->iface);
          struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache,a_hdr->ar_sip);

          sr_ethernet_hdr_t *e_reply = (sr_ethernet_hdr_t *)(reply_pac->buf);
          int j;
          for (j=0; j<ETHER_ADDR_LEN; j++){
            e_reply->ether_shost[j] = if_list->addr[j];
            e_reply->ether_dhost[j] = entry->mac[j];
          }
          
          print_hdrs(reply_pac->buf,reply_pac->len);
          sr_send_packet(sr,reply_pac->buf,reply_pac->len,reply_pac->iface);
          free(entry);
        }
        sr_arpreq_destroy(&sr->cache,req);
      }
    }
    else{
      Debug("Not for me, re-route!\n");
      reroute_packet(sr,packet,len,interface);
    }
  }
  else if(ntohs(a_hdr->ar_op) == 1){
    Debug("This is a request\n");
    handle_arpeq(sr,packet,ret_pac,len,interface);
  }
  else{
    fprintf(stderr, "ARP op-code %u isn't handled\n", ntohs(a_hdr->ar_op));
  }
}

void reroute_packet(struct sr_instance* sr /* borrowed */,
                         uint8_t* packet /* borrowed */ ,
                         unsigned int len,
                         const char* iface /* borrowed */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(iface);

    if (sr->nat && ethertype(packet)==ethertype_ip){
      Debug("%s\n",iface);
      if (sr_handle_nat(sr,packet,len,iface)==1)
        return;
    }
    sr_ethernet_hdr_t *ethHeader = (sr_ethernet_hdr_t *)(packet);    

    uint32_t ip;
    uint16_t ethtype = ethertype(packet);
    if(ethtype == ethertype_ip){
      ip = ((sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr)))->ip_dst;
      ethHeader->ether_type = ntohs(ethertype_arp);
    }else if (ethtype == ethertype_arp){
      ip = ((sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)))->ar_tip;
    }else{
      fprintf(stderr, "Unhandled Ethernet type, cannot route %d\n", ethtype);
      return;
    }

/*    print_addr_ip_int(ip);*/

    struct sr_rt* rt = sr->routing_table;
    for(;rt != NULL; rt=rt->next){
      if((rt->gw).s_addr == ip){
        break;
      }
    }
/*    print_hdrs(packet,len);*/
    assert(rt);

    struct sr_if* out_iface = sr_get_interface(sr,rt->interface);
    assert(out_iface);
    unsigned char* iface_addr = out_iface->addr;
    
    if(ethtype == ethertype_ip){
      sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
      ip_hdr->ip_ttl--;
      ip_hdr->ip_sum=0;
      ip_hdr->ip_sum=cksum(ip_hdr,sizeof(sr_ip_hdr_t));
    }

    /*Check cache for mac*/
    struct sr_arpentry* arp_loc;
    if ((arp_loc=sr_arpcache_lookup(&(sr->cache),ip)) == NULL){
      /*Send arp request out of interface if no mac*/
      Debug("Caching Packet\n");
      print_hdrs(packet,len);
      sr_arpcache_queuereq(&(sr->cache),ip,packet,len,out_iface->name);

      sr_arp_hdr_t* arpHeader = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)); 
     
      int i;
      for(i=0;i<ETHER_ADDR_LEN;i++){
        ethHeader->ether_dhost[i] =0xFF;
        ethHeader->ether_shost[i] = iface_addr[i];
        arpHeader->ar_sha[i] = iface_addr[i];
        arpHeader->ar_tha[i]= 0x0000;
      }
      /* Set ARP header */
      arpHeader->ar_hrd=ntohs(0x0001);
      arpHeader->ar_pro=ntohs(0x0800);
      arpHeader->ar_hln=0x0006;
      arpHeader->ar_pln=0x0004;
      arpHeader->ar_op=ntohs(0x0001);
      arpHeader->ar_sip=out_iface->ip;
      arpHeader->ar_tip=ip;

      Debug("Sending ARP request\n");
      print_hdrs(packet,len);
      sr_send_packet(sr,packet,len,out_iface->name);
      /*free(req);*/
    }
    else{
      Debug("ARP Cache found, re-routing packet\n");
      /*Send with mac if it's there*/
      sr_ethernet_hdr_t *e_pac = (sr_ethernet_hdr_t *)(packet); 
      int i;
      for(i=0;i<ETHER_ADDR_LEN;i++){
        e_pac->ether_dhost[i] = arp_loc->mac[i];
        e_pac->ether_shost[i] = iface_addr[i];
      }
      free(arp_loc);
      print_hdrs(packet,len);
      sr_send_packet(sr,packet,len,out_iface->name); 
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
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), (uint32_t)(rt->gw.s_addr), packet, 
                                                 len, rt->interface);

    send_request(sr, req->ip);
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
  if(sr->nat == NULL)
    return 0;
  Debug("Applying NAT\n");
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