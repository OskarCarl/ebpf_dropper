// from uapi/linux/ip.h
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	/*The options start here. */
};

// from uapi/linux/udp.h
struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};

// from uapi/linux/tcp.h
struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

// from	uapi/linux/pkt_cls.h
#define	TC_ACT_UNSPEC       (-1)
#define	TC_ACT_OK           0
#define	TC_ACT_RECLASSIFY   1
#define	TC_ACT_SHOT         2
#define	TC_ACT_PIPE         3
#define	TC_ACT_STOLEN       4
#define	TC_ACT_QUEUED       5
#define	TC_ACT_REPEAT       6
#define	TC_ACT_REDIRECT     7
#define	TC_ACT_TRAP         8
