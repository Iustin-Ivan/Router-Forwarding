#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "include/queue.h"
#include "include/lib.h"
#include "include/protocols.h"
#include "include/list.h"
#include <arpa/inet.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

char MAC_BROADCAST_ADDR[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// use this to retain the original packet
typedef struct packet {
	char *payload;
	size_t len;
	int interface;
} packet;

struct route_table_entry *get_best_route(uint32_t ip_dest, int rtable_len, struct route_table_entry *rtable)
{
	/* TODO 2.2: Implement the LPM algorithm */
	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++)*/
	struct route_table_entry *best = NULL;
	for (int i = 0; i < rtable_len; i++)
	{
		if ((ip_dest & rtable[i].mask) == rtable[i].prefix)
		{

			if (best == NULL)
				best = &rtable[i];
			else if (ntohl(best->mask) < ntohl(rtable[i].mask))
			{
				best = &rtable[i];
			}
		}
	}

	return best;
}

struct arp_entry *get_arp_entry(uint32_t ip_dest, int arp_table_len, struct arp_entry *arp_table)
{
	/* TODO 2.4: Iterate through the MAC table and search for an entry
	 * that matches ip_dest. */

	/* We can iterate thrpigh the mac_table for (int i = 0; i <
	 * mac_table_len; i++) */

	for (int i = 0; i <= arp_table_len; i++)
	{
		if (arp_table[i].ip == 0) {
			return NULL;
		}
		if (arp_table[i].ip == ip_dest)
		{
			return &arp_table[i];
		}
	}
	return NULL;
}

void sendResponse(char *buf, uint16_t type, int interface, size_t len) {
	char resp[MAX_PACKET_LEN];
	int resp_len = 0;

    // initial headers
	struct ether_header *eth_hdr_1 = (struct ether_header *) buf;
	struct iphdr *ip_hdr_1 = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr_1 = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	// response headers
	struct ether_header *eth_hdr_2 = (struct ether_header *) resp;
	struct iphdr *ip_hdr_2 = (struct iphdr *)(resp + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr_2 = (struct icmphdr *)(resp + sizeof(struct ether_header) + sizeof(struct iphdr));
    uint8_t *mem = (uint8_t *)(resp + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));

    // if not ping
	if (type != 0) {
	// copy 64B from the payload
	memcpy(mem, ip_hdr_1, 64);

	resp_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;

    // send back where it came from ether header
	memcpy(eth_hdr_2->ether_dhost, eth_hdr_1->ether_shost, 6);
	memcpy(eth_hdr_2->ether_shost, eth_hdr_1->ether_dhost, 6);
	eth_hdr_2->ether_type = htons(ETHERTYPE_IP);

	memcpy(ip_hdr_2, ip_hdr_1, sizeof(struct iphdr));

    // switch the sender and receiver ip header
	ip_hdr_2->daddr = ip_hdr_1->saddr;
	ip_hdr_2->saddr = ip_hdr_1->daddr;

	ip_hdr_2->protocol = 1;
	ip_hdr_2->ttl = 64;
	ip_hdr_2->check = 0;
	ip_hdr_2->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + 64);
	icmp_hdr_2->type = type;
	icmp_hdr_2->code = 0;
	ip_hdr_2->check = htons(checksum((uint16_t*) (ip_hdr_2), sizeof(struct iphdr)));

	send_to_link(interface, resp, resp_len);
	
	} else {
		// if ping almost the same but keep the whole payload not just 64B
		uint8_t aux[6];
        memcpy(aux, eth_hdr_1->ether_dhost, 6);
		memcpy(eth_hdr_1->ether_dhost, eth_hdr_1->ether_shost, 6);
		memcpy(eth_hdr_1->ether_shost, aux, 6);

		uint32_t aux2 = ip_hdr_1->daddr;
		ip_hdr_1->daddr = ip_hdr_1->saddr;
		ip_hdr_1->saddr = aux2;
		ip_hdr_1->ttl--;

		icmp_hdr_1->type = type;
		icmp_hdr_1->code = 0;
		icmp_hdr_1->checksum = 0;
		icmp_hdr_1->checksum = htons(checksum((uint16_t*) (icmp_hdr_1), sizeof(struct icmphdr)));
		ip_hdr_1->check = 0;
		ip_hdr_1->check = htons(checksum((uint16_t*) (ip_hdr_1), sizeof(struct iphdr)));
		
		send_to_link(interface, buf, len);
	}
}

void reply_arp(packet *m, struct in_addr router_address) {

	struct ether_header *eth_hdr = (struct ether_header*) m->payload;
	struct arp_header *arphdr = (struct arp_header*)(m->payload + sizeof(struct ether_header));

	// request code becomes reply code
	arphdr->op = htons(2);

	// swap the receiver and the sender arp and ether
	arphdr->tpa = arphdr->spa;
	memcpy(arphdr->tha, arphdr->sha, 6);

	get_interface_mac(m->interface, arphdr->sha);
	arphdr->spa = router_address.s_addr;

	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(m->interface, eth_hdr->ether_shost);

	send_to_link(m->interface, m->payload, m->len);
}

void add_arp_from_reply(packet *m, struct arp_entry *arptable, int *arptable_len, queue *waitingPackets) {
	    struct arp_header *arphdr = (struct arp_header*)(m->payload + sizeof(struct ether_header));

		// Enter entry in table.
		arptable[*arptable_len].ip = arphdr->spa;
		memcpy(arptable[*arptable_len].mac, arphdr->sha, 6);
		++(*arptable_len);

		// send the waiting packets if they needed the mac in order to be sent else put them back in the queue 
		while(!queue_empty(*waitingPackets)) {
			packet *p = queue_deq(*waitingPackets);
			struct ether_header *eth_hdr = (struct ether_header*) (p->payload);
			memcpy(eth_hdr->ether_dhost, arptable[*arptable_len - 1].mac, 6);
			send_to_link(p->interface, p->payload, p->len);
			}
}

void request_arp(uint32_t destip, int interface) {

	size_t len = sizeof(struct ether_header) + sizeof(struct arp_header);
	char buf[len];

	struct ether_header *ethhdr = (struct ether_header*) (buf);
	struct arp_header *arphdr = (struct arp_header*)(buf + sizeof(struct ether_header));

	struct in_addr router_addr;
	inet_aton(get_interface_ip(interface), &router_addr);

	ethhdr->ether_type = htons(ETHERTYPE_ARP);

	// Broadcast for destination, router for source
	memcpy(ethhdr->ether_dhost, MAC_BROADCAST_ADDR, 6);
	get_interface_mac(interface, ethhdr->ether_shost);

	arphdr->htype = htons(1);
	arphdr->ptype = htons(ETHERTYPE_IP); // ARP included in IP
	arphdr->hlen = 6;
	arphdr->plen = 4;
	arphdr->op = htons(1);

	// duplicate the source mac and ip from ether to arp
	memcpy(arphdr->sha, ethhdr->ether_shost, 6);
	arphdr->spa = router_addr.s_addr;

	memcpy(arphdr->tha, MAC_BROADCAST_ADDR, 6);
	arphdr->tpa = destip;

	send_to_link(interface, buf, len);
}

void add_entry_arp(struct arp_entry *arp_table, int *arp_table_len, uint32_t router_address, uint8_t *router_mac) {
	arp_table[*arp_table_len].ip = router_address;
	memcpy(arp_table[*arp_table_len].mac, router_mac, 6);
	++(*arp_table_len);
} // this is for router and for who sends to the router the other func is for arp reply 
  // when there is no need for dequeing packets use this one

int main(int argc, char *argv[])
{
	int interface;
	char buf[MAX_PACKET_LEN];
	size_t len;

	/* Don't touch this */
	init(argc - 2, argv + 2);

	/* Routing table */
    struct route_table_entry *rtable;
    int rtable_len;

    /* Mac table */
    struct arp_entry *arp_table;
    int arp_table_len;

	queue packq = queue_create();

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 200000);

	arp_table = calloc(200000, sizeof(struct arp_entry));

	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);
	// arp_table_len = parse_arp_table("checker/arp_table.txt", arp_table);
    arp_table_len = 0;

	while (1)
	{
		/* We call get_packet to receive a packet. get_packet returns
		the interface it has received the data from. And writes to
		len the size of the packet. */

		interface = recv_from_any_link(buf, &len);
		packet *p = malloc(sizeof(packet));
		p->len = len;
		p->interface = interface;
		p->payload = malloc(len);
		memcpy(p->payload, buf, len);

		struct in_addr router_address;
		inet_aton(get_interface_ip(interface), &router_address);

		uint8_t router_mac[6];
		get_interface_mac(interface, router_mac);

		if (get_arp_entry(router_address.s_addr, arp_table_len, arp_table) == NULL) {
			add_entry_arp(arp_table, &arp_table_len, router_address.s_addr, router_mac);
		}

		/* Extract the Ethernet header from the packet. Since protocols are
		 * stacked, the first header is the ethernet header, the next header is
		 * at m.payload + sizeof(struct ether_header) */
		struct ether_header *eth_hdr = (struct ether_header *)buf;
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
		    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
			
			if (get_arp_entry(ip_hdr->saddr, arp_table_len, arp_table) == NULL) {
				add_entry_arp(arp_table, &arp_table_len, ip_hdr->saddr, eth_hdr->ether_shost);
			}

		/* TODO 2.1: Check the ip_hdr integrity using ip_checksum(ip_hdr, sizeof(struct iphdr)) */
		    uint16_t former_check = ip_hdr->check;
		    ip_hdr->check = 0;
		    if (former_check != htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))))
		    {
			    goto f;
		    }

			/* TODO 2.3: Check TTL >= 1. Update TLL. Update checksum using the incremental forumla  */
		    if (ip_hdr->ttl <= 1)
		    {
			   sendResponse(buf, 11, interface, len);
			   goto f;
		    }
		    uint16_t old_ttl;
		    old_ttl = ip_hdr->ttl;
		    ip_hdr->ttl--;

		    ip_hdr->check = ~(~former_check + ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

			if(ip_hdr->protocol == 1 && (ip_hdr->daddr == router_address.s_addr) && (icmp_hdr->type == 8)) {
                sendResponse(buf, 0, interface, len);
				goto f;
			}

		/* TODO 2.2: Call get_best_route to find the most specific route, continue; (drop) if null */
		    struct route_table_entry *chosen_road = get_best_route(ip_hdr->daddr, rtable_len, rtable);
		    if (chosen_road == NULL)
		    {
				sendResponse(buf, 3, interface, len);
			    goto f;
		    }

		/* TODO 2.4: Update the ethernet addresses. Use get_mac_entry to find the destination MAC
		 * address. Use get_interface_mac(m.interface, uint8_t *mac) to
		 * find the mac address of our interface. */
		    struct arp_entry *dest_mac = get_arp_entry(chosen_road->next_hop, arp_table_len, arp_table);
		    if (dest_mac == NULL)
		    {
			memcpy(p->payload, buf, len);
			request_arp(chosen_road->next_hop, chosen_road->interface);

			// router is source
			struct ether_header *eth_hdr_pack = (struct ether_header *)(p->payload);
			get_interface_mac(chosen_road->interface, eth_hdr_pack->ether_shost);


		    // save the interface for dequeue and sending
			p->interface = chosen_road->interface;
            
			// introduce in the queue
			queue_enq(packq, p);
			goto f;
		    }

		    memcpy(eth_hdr->ether_dhost, dest_mac->mac, 6);
		    get_interface_mac(chosen_road->interface, eth_hdr->ether_shost);

		    // Call send_to_link(chosen_road->interface, packet, len);
		    printf("Packet transmis pe %d!\n", chosen_road->interface);
		    send_to_link(chosen_road->interface, buf, len);
f:
            continue;
		    } else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			    struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
				if ((ntohs(arp_hdr->op) == 1) && (arp_hdr->tpa == router_address.s_addr)) { // ARP request for me
                    reply_arp(p, router_address);
	            } else if ((ntohs(arp_hdr->op) == 2) && arp_hdr->tpa == router_address.s_addr){ // ARP reply for me
					add_arp_from_reply(p, arp_table ,&arp_table_len, &packq);
				}
            }
}
}


