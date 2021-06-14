#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_HOST
#endif

#if defined(_WIN32) || defined(_WIN64)
typedef unsigned int lsearch_cnt_t;
#else
typedef size_t lsearch_cnt_t;
#endif

#pragma pack(1)

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// from pcap.h
#define TCPDUMP_MAGIC 0xa1b2c3d4
#define TCPDUMP_CIGAM 0xd4c3b2a1

#define TCPDUMP_DECODE_LEN 65535

#define DLT_IEEE802_11 105 /* IEEE 802.11 wireless */
#define DLT_IEEE802_11_PRISM 119
#define DLT_IEEE802_11_RADIO 127
#define DLT_IEEE802_11_PPI_HDR 192

struct pcap_file_header
{
  u32 magic;
  u16 version_major;
  u16 version_minor;
  u32 thiszone; /* gmt to local correction */
  u32 sigfigs;  /* accuracy of timestamps */
  u32 snaplen;  /* max length saved portion of each pkt */
  u32 linktype; /* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr
{
  u32 tv_sec;  /* timestamp seconds */
  u32 tv_usec; /* timestamp microseconds */
  u32 caplen;  /* length of portion present */
  u32 len;     /* length this packet (off wire) */
};

typedef struct pcap_file_header pcap_file_header_t;
typedef struct pcap_pkthdr pcap_pkthdr_t;

// from linux/ieee80211.h
struct ieee80211_hdr_3addr
{
  u16 frame_control;
  u16 duration_id;
  u8 addr1[6];
  u8 addr2[6];
  u8 addr3[6];
  u16 seq_ctrl;

} __attribute__((packed));

struct ieee80211_qos_hdr
{
  u16 frame_control;
  u16 duration_id;
  u8 addr1[6];
  u8 addr2[6];
  u8 addr3[6];
  u16 seq_ctrl;
  u16 qos_ctrl;

} __attribute__((packed));

typedef struct ieee80211_hdr_3addr ieee80211_hdr_3addr_t;
typedef struct ieee80211_qos_hdr ieee80211_qos_hdr_t;

struct ieee80211_llc_snap_header
{
  /* LLC part: */
  u8 dsap; /**< Destination SAP ID */
  u8 ssap; /**< Source SAP ID */
  u8 ctrl; /**< Control information */

  /* SNAP part: */
  u8 oui[3];     /**< Organization code, usually 0 */
  u16 ethertype; /**< Ethernet Type field */

} __attribute__((packed));

typedef struct ieee80211_llc_snap_header ieee80211_llc_snap_header_t;

#define IEEE80211_FCTL_FTYPE 0x000c
#define IEEE80211_FCTL_STYPE 0x00f0
#define IEEE80211_FCTL_TODS 0x0100
#define IEEE80211_FCTL_FROMDS 0x0200

#define IEEE80211_FTYPE_MGMT 0x0000
#define IEEE80211_FTYPE_DATA 0x0008

#define IEEE80211_STYPE_PROBE_REQ 0x0040

/* Management Frame Information Element Types */
#define MFIE_TYPE_SSID 0

// radiotap header from http://www.radiotap.org/
struct ieee80211_radiotap_header
{
  u8 it_version; /* set to 0 */
  u8 it_pad;
  u16 it_len;     /* entire length */
  u32 it_present; /* fields present */

} __attribute__((packed));

typedef struct ieee80211_radiotap_header ieee80211_radiotap_header_t;

// prism header
#define WLAN_DEVNAMELEN_MAX 16

struct prism_item
{
  u32 did;
  u16 status;
  u16 len;
  u32 data;

} __attribute__((packed));

struct prism_header
{
  u32 msgcode;
  u32 msglen;

  char devname[WLAN_DEVNAMELEN_MAX];

  struct prism_item hosttime;
  struct prism_item mactime;
  struct prism_item channel;
  struct prism_item rssi;
  struct prism_item sq;
  struct prism_item signal;
  struct prism_item noise;
  struct prism_item rate;
  struct prism_item istx;
  struct prism_item frmlen;

} __attribute__((packed));

typedef struct prism_header prism_header_t;

/* CACE PPI headers */
struct ppi_packet_header
{
  uint8_t pph_version;
  uint8_t pph_flags;
  uint16_t pph_len;
  uint32_t pph_dlt;
} __attribute__((packed));

typedef struct ppi_packet_header ppi_packet_header_t;

#define MAX_ESSID_LEN 32

typedef struct
{
  u8 bssid[6];
  char essid[MAX_ESSID_LEN + 4];
  int essid_len;
  int essid_source;

} essid_t;

#define BROADCAST_MAC "\xff\xff\xff\xff\xff\xff"

// functions
static u16 byte_swap_16(const u16 n)
{
  return (n & 0xff00) >> 8 | (n & 0x00ff) << 8;
}

static u32 byte_swap_32(const u32 n)
{
  return (n & 0xff000000) >> 24 | (n & 0x00ff0000) >> 8 | (n & 0x0000ff00) << 8 | (n & 0x000000ff) << 24;
}

static u64 byte_swap_64(const u64 n)
{
  return (n & 0xff00000000000000ULL) >> 56 | (n & 0x00ff000000000000ULL) >> 40 | (n & 0x0000ff0000000000ULL) >> 24 | (n & 0x000000ff00000000ULL) >> 8 | (n & 0x00000000ff000000ULL) << 8 | (n & 0x0000000000ff0000ULL) << 24 | (n & 0x000000000000ff00ULL) << 40 | (n & 0x00000000000000ffULL) << 56;
}

static int get_essid_from_tag(const u8 *packet, const pcap_pkthdr_t *header, u32 length_skip, essid_t *essid)
{
  if (length_skip > header->caplen)
    return -1;

  u32 length = header->caplen - length_skip;

  const u8 *beacon = packet + length_skip;

  const u8 *cur = beacon;
  const u8 *end = beacon + length;

  while (cur < end)
  {
    if ((cur + 2) >= end)
      break;

    u8 tagtype = *cur++;
    u8 taglen = *cur++;

    if ((cur + taglen) >= end)
      break;

    if (tagtype == MFIE_TYPE_SSID)
    {
      if (taglen < MAX_ESSID_LEN)
      {
        memcpy(essid->essid, cur, taglen);

        essid->essid_len = taglen;

        return 0;
      }
    }

    cur += taglen;
  }

  return -1;
}

static void process_packet(const u8 *packet, const pcap_pkthdr_t *header)
{

  if (header->caplen < sizeof(ieee80211_hdr_3addr_t))
    return;

  // our first header: ieee80211
  ieee80211_hdr_3addr_t *ieee80211_hdr_3addr = (ieee80211_hdr_3addr_t *)packet;

#ifdef BIG_ENDIAN_HOST
  ieee80211_hdr_3addr->frame_control = byte_swap_16(ieee80211_hdr_3addr->frame_control);
  ieee80211_hdr_3addr->duration_id = byte_swap_16(ieee80211_hdr_3addr->duration_id);
  ieee80211_hdr_3addr->seq_ctrl = byte_swap_16(ieee80211_hdr_3addr->seq_ctrl);
#endif

  const u16 frame_control = ieee80211_hdr_3addr->frame_control;

  if ((frame_control & IEEE80211_FCTL_FTYPE) == IEEE80211_FTYPE_MGMT)
  {
    essid_t essid;

    memset(&essid, 0, sizeof(essid_t));

    const int stype = frame_control & IEEE80211_FCTL_STYPE;

    if (stype == IEEE80211_STYPE_PROBE_REQ)
    {
      const u32 length_skip = sizeof(ieee80211_hdr_3addr_t);

      const int rc_beacon = get_essid_from_tag(packet, header, length_skip, &essid);

      if (rc_beacon == -1)
        return;

      if (essid.essid_len == 0)
        return;
      printf("%02x:%02x:%02x:%02x:%02x:%02x\t",
             ieee80211_hdr_3addr->addr2[0],
             ieee80211_hdr_3addr->addr2[1],
             ieee80211_hdr_3addr->addr2[2],
             ieee80211_hdr_3addr->addr2[3],
             ieee80211_hdr_3addr->addr2[4],
             ieee80211_hdr_3addr->addr2[5]);

      if (memcmp(ieee80211_hdr_3addr->addr3, BROADCAST_MAC, 6) == 0)
      {
        printf("(not associated)");
      }
      else
      {
        printf("%02x:%02x:%02x:%02x:%02x:%02x",
               ieee80211_hdr_3addr->addr3[0],
               ieee80211_hdr_3addr->addr3[1],
               ieee80211_hdr_3addr->addr3[2],
               ieee80211_hdr_3addr->addr3[3],
               ieee80211_hdr_3addr->addr3[4],
               ieee80211_hdr_3addr->addr3[5]);
      }

      printf("\t%s\n", essid.essid);
    }
  }
}

int main(int argc, char *argv[])
{
  if (argc != 2)
  {
    fprintf(stderr, "usage: %s input.pcap\n", argv[0]);

    return -1;
  }

  char *in = argv[1];

  // start with pcap handling
  FILE *pcap = fopen(in, "rb");

  if (pcap == NULL)
  {
    fprintf(stderr, "%s: %s\n", in, strerror(errno));
    return -1;
  }

  // check pcap header
  pcap_file_header_t pcap_file_header;

  const int nread = fread(&pcap_file_header, sizeof(pcap_file_header_t), 1, pcap);

  if (nread != 1)
  {
    fprintf(stderr, "%s: Could not read pcap header\n", in);
    return -1;
  }

#ifdef BIG_ENDIAN_HOST
  pcap_file_header.magic = byte_swap_32(pcap_file_header.magic);
  pcap_file_header.version_major = byte_swap_16(pcap_file_header.version_major);
  pcap_file_header.version_minor = byte_swap_16(pcap_file_header.version_minor);
  pcap_file_header.thiszone = byte_swap_32(pcap_file_header.thiszone);
  pcap_file_header.sigfigs = byte_swap_32(pcap_file_header.sigfigs);
  pcap_file_header.snaplen = byte_swap_32(pcap_file_header.snaplen);
  pcap_file_header.linktype = byte_swap_32(pcap_file_header.linktype);
#endif

  int bitness = 0;

  if (pcap_file_header.magic == TCPDUMP_MAGIC)
  {
    bitness = 0;
  }
  else if (pcap_file_header.magic == TCPDUMP_CIGAM)
  {
    bitness = 1;
  }
  else
  {
    fprintf(stderr, "%s: Invalid pcap header\n", in);
    return 1;
  }

  if (bitness == 1)
  {
    pcap_file_header.magic = byte_swap_32(pcap_file_header.magic);
    pcap_file_header.version_major = byte_swap_16(pcap_file_header.version_major);
    pcap_file_header.version_minor = byte_swap_16(pcap_file_header.version_minor);
    pcap_file_header.thiszone = byte_swap_32(pcap_file_header.thiszone);
    pcap_file_header.sigfigs = byte_swap_32(pcap_file_header.sigfigs);
    pcap_file_header.snaplen = byte_swap_32(pcap_file_header.snaplen);
    pcap_file_header.linktype = byte_swap_32(pcap_file_header.linktype);
  }

  if ((pcap_file_header.linktype != DLT_IEEE802_11) && (pcap_file_header.linktype != DLT_IEEE802_11_PRISM) && (pcap_file_header.linktype != DLT_IEEE802_11_RADIO) && (pcap_file_header.linktype != DLT_IEEE802_11_PPI_HDR))
  {
    fprintf(stderr, "%s: Unsupported linktype detected\n", in);
    return -1;
  }

  // walk the packets
  while (!feof(pcap))
  {
    pcap_pkthdr_t header;

    const int nread1 = fread(&header, sizeof(pcap_pkthdr_t), 1, pcap);

    if (nread1 != 1)
      continue;

#ifdef BIG_ENDIAN_HOST
    header.tv_sec = byte_swap_32(header.tv_sec);
    header.tv_usec = byte_swap_32(header.tv_usec);
    header.caplen = byte_swap_32(header.caplen);
    header.len = byte_swap_32(header.len);
#endif

    if (bitness == 1)
    {
      header.tv_sec = byte_swap_32(header.tv_sec);
      header.tv_usec = byte_swap_32(header.tv_usec);
      header.caplen = byte_swap_32(header.caplen);
      header.len = byte_swap_32(header.len);
    }

    u8 packet[TCPDUMP_DECODE_LEN];

    if (header.caplen >= TCPDUMP_DECODE_LEN || (signed)header.caplen < 0)
    {
      fprintf(stderr, "%s: Oversized packet detected\n", in);

      break;
    }

    const u32 nread2 = fread(&packet, sizeof(u8), header.caplen, pcap);

    if (nread2 != header.caplen)
    {
      fprintf(stderr, "%s: Could not read pcap packet data\n", in);

      break;
    }

    u8 *packet_ptr = packet;

    if (pcap_file_header.linktype == DLT_IEEE802_11_PRISM)
    {
      if (header.caplen < sizeof(prism_header_t))
      {
        fprintf(stderr, "%s: Could not read prism header\n", in);

        break;
      }

      prism_header_t *prism_header = (prism_header_t *)packet;

#ifdef BIG_ENDIAN_HOST
      prism_header->msgcode = byte_swap_32(prism_header->msgcode);
      prism_header->msglen = byte_swap_32(prism_header->msglen);
#endif

      if ((signed)prism_header->msglen < 0)
      {
        fprintf(stderr, "%s: Oversized packet detected\n", in);

        break;
      }

      if ((signed)(header.caplen - prism_header->msglen) < 0)
      {
        fprintf(stderr, "%s: Oversized packet detected\n", in);

        break;
      }

      packet_ptr += prism_header->msglen;
      header.caplen -= prism_header->msglen;
      header.len -= prism_header->msglen;
    }
    else if (pcap_file_header.linktype == DLT_IEEE802_11_RADIO)
    {
      if (header.caplen < sizeof(ieee80211_radiotap_header_t))
      {
        fprintf(stderr, "%s: Could not read radiotap header\n", in);

        break;
      }

      ieee80211_radiotap_header_t *ieee80211_radiotap_header = (ieee80211_radiotap_header_t *)packet;

#ifdef BIG_ENDIAN_HOST
      ieee80211_radiotap_header->it_len = byte_swap_16(ieee80211_radiotap_header->it_len);
      ieee80211_radiotap_header->it_present = byte_swap_32(ieee80211_radiotap_header->it_present);
#endif

      if (ieee80211_radiotap_header->it_version != 0)
      {
        fprintf(stderr, "%s: Invalid radiotap header\n", in);

        break;
      }

      packet_ptr += ieee80211_radiotap_header->it_len;
      header.caplen -= ieee80211_radiotap_header->it_len;
      header.len -= ieee80211_radiotap_header->it_len;
    }
    else if (pcap_file_header.linktype == DLT_IEEE802_11_PPI_HDR)
    {
      if (header.caplen < sizeof(ppi_packet_header_t))
      {
        fprintf(stderr, "%s: Could not read ppi header\n", in);

        break;
      }

      ppi_packet_header_t *ppi_packet_header = (ppi_packet_header_t *)packet;

#ifdef BIG_ENDIAN_HOST
      ppi_packet_header->pph_len = byte_swap_16(ppi_packet_header->pph_len);
#endif

      packet_ptr += ppi_packet_header->pph_len;
      header.caplen -= ppi_packet_header->pph_len;
      header.len -= ppi_packet_header->pph_len;
    }

    process_packet(packet_ptr, &header);
  }

  fclose(pcap);

  return 0;
}
