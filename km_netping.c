#include "km_netping.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ivannikov Igor");

static unsigned int nf_hookpack(void *priv, struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	/* Input headers (request) */
	struct iphdr	*ip;
	struct icmphdr	*icmp;

	/* Output headers (reply) */
	struct sk_buff	*skbr;
	struct iphdr	*ipr;
	struct icmphdr	*icmpr;

	struct net	*net;
	struct rtable	*rtable;
	struct flowi4	fl4;
	unsigned int	len_skb;
	unsigned int	len_icmp;

	/* Filtering traffic. Drop the only ICMP requests */
	ip	= ip_hdr(skb);
	icmp	= icmp_hdr(skb);
	if (ip->protocol != IPPROTO_ICMP || icmp->type != ICMP_ECHO)
		goto skip_packet;

	/*
	 * Prepares structure skb_reply.
	 * In this case, it is not necessary to keep room for the tail
	 * and the head.
	 */
	len_icmp = ntohs(ip->tot_len) - sizeof(struct iphdr);
	len_skb	= sizeof(struct ethhdr) + sizeof(struct iphdr) + len_icmp;
	skbr = alloc_skb(len_skb, GFP_ATOMIC);
	if (!skbr)
		goto error_alloc;
	skbr->sk	= skb->sk;
	skbr->dev	= state->in;
	skb_reserve(skbr, len_skb);

	net		= dev_net(skbr->dev);
	fl4.daddr	= ip->saddr;
	fl4.saddr	= ip->daddr;
	fl4.flowi4_oif	= skbr->dev->ifindex;
	rtable		= ip_route_output_key(net, &fl4);
	skb_dst_set(skbr, &rtable->dst);
		if (skb_dst(skb)->error)
			goto error_dst;

	/* Prepares ICMP header */
	skb_push(skbr, len_icmp);
	skb_reset_transport_header(skbr);
	icmpr = icmp_hdr(skbr);
	memmove(icmpr, icmp, len_icmp);
	icmpr->type	= ICMP_ECHOREPLY;
	icmpr->checksum = 0;
	icmpr->checksum = ip_compute_csum((void *)icmpr, len_icmp);

	/* Prepares IP header */
	skb_push(skbr, sizeof(struct iphdr));
	skb_reset_network_header(skbr);
	ipr = ip_hdr(skbr);
	memmove(ipr, ip, sizeof(struct iphdr));
	ipr->saddr	= ip->daddr;
	ipr->daddr	= ip->saddr;
	ipr->check	= ip_compute_csum((void *)ipr, sizeof(struct iphdr));

	/*
	 * Do not remove the structure skbr. This will be done automatically
	 * once the package sending.
	 */
	ip_local_out(net, skbr->sk, skbr);
	return NF_DROP;

error_dst:
	pr_info("nf_hookpack: A set dst error\n");
	kfree_skb(skbr);
	return NF_ACCEPT;

error_alloc:
	pr_info("nf_hookpack: A memory allocation error");
	return NF_ACCEPT;

skip_packet:
	return NF_ACCEPT;
}

static struct nf_hook_ops nfhops;

static int kmnet_init(void)
{
	memset(&nfhops, 0, sizeof(nfhops));
	nfhops.hook	= nf_hookpack;
	nfhops.pf	= PF_INET;
	nfhops.hooknum	= NF_INET_LOCAL_IN;
	nfhops.priority	= NF_IP_PRI_FIRST;
	nf_register_hook(&nfhops);

	pr_info("module_init: Module installed");
	return 0;
}

static void kmnet_exit(void)
{
	nf_unregister_hook(&nfhops);
	pr_info("module_exit: Module removed");
}

module_init(kmnet_init);
module_exit(kmnet_exit);