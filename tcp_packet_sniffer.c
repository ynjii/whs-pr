#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include "myheader.h"

// 이더넷 MAC 주소를 출력하는 함수
void print_mac_address(u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", 
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 패킷 데이터를 16진수와 ASCII로 출력하는 함수
void print_payload(const u_char *payload, int len) {
    int i;
    int gap;
    const u_char *ch;

    // 데이터가 없으면 반환
    if (len <= 0)
        return;

    // 최대 바이트 수 제한 (너무 많은 데이터 출력 방지)
    int max_len = (len > 64) ? 64 : len;
    
    printf("\n   Payload (%d bytes):\n", len);
    
    // 헥사값과 ASCII값 출력
    for (i = 0; i < max_len; i++) {
        if (i % 16 == 0) {
            if (i != 0)
                printf("  ");
            printf("   ");
            ch = payload + i - 16;
            for (gap = 0; gap < 16 && i - 16 + gap < max_len; gap++) {
                printf("%c", (isprint(*(ch + gap))) ? *(ch + gap) : '.');
            }
            printf("\n   ");
        }
        
        printf("%02x ", payload[i]);
    }
    
    // 마지막 줄 정렬
    gap = max_len % 16;
    if (gap != 0) {
        for (i = 0; i < (16 - gap); i++) {
            printf("   ");
        }
        printf("  ");
        
        ch = payload + max_len - gap;
        for (i = 0; i < gap; i++) {
            printf("%c", (isprint(*(ch + i))) ? *(ch + i) : '.');
        }
    }
    printf("\n");
}

// HTTP 메시지인지 확인하고 읽기 쉽게 출력하는 함수
void print_http_message(const u_char *payload, int len) {
    if (len <= 0)
        return;

    // HTTP 요청 또는 응답인지 확인 (간단한 체크)
    if (len >= 4 && (
        (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') ||
        (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T') ||
        (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P') ||
        (payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D')
    )) {
        printf("\n=== HTTP Message ===\n");
        
        // HTTP 헤더와 본문을 나누는 빈 줄 찾기
        const u_char *body = NULL;
        for (int i = 0; i < len - 3; i++) {
            if (payload[i] == '\r' && payload[i+1] == '\n' && 
                payload[i+2] == '\r' && payload[i+3] == '\n') {
                body = &payload[i+4];
                break;
            }
        }
        
        // 헤더 부분만 읽기 쉽게 출력 (최대 1500바이트)
        int header_len = body ? (body - payload) : len;
        int display_len = header_len > 1500 ? 1500 : header_len;
        
        printf("--- HTTP Headers ---\n");
        // 줄 단위로 출력
        const u_char *current = payload;
        const u_char *end = payload + display_len;
        const u_char *line_start = current;
        
        while (current < end) {
            if (*current == '\r' && *(current + 1) == '\n') {
                printf("   ");
                for (const u_char *p = line_start; p < current; p++) {
                    printf("%c", isprint(*p) ? *p : '.');
                }
                printf("\n");
                current += 2; // CRLF 건너뛰기
                line_start = current;
            } else {
                current++;
            }
        }
        
        // 본문이 있으면 간략하게 출력
        if (body) {
            int body_len = len - header_len;
            printf("\n--- HTTP Body ---\n");
            printf("   [HTTP Body length: %d bytes]\n", body_len);
            
            // 본문의 일부만 출력 (최대 200바이트)
            int display_body_len = body_len > 200 ? 200 : body_len;
            printf("   Preview: ");
            for (int i = 0; i < display_body_len; i++) {
                if (body[i] == '\r' || body[i] == '\n') {
                    printf(" ");
                } else {
                    printf("%c", isprint(body[i]) ? body[i] : '.');
                }
            }
            if (body_len > 200) {
                printf("... (더 많은 데이터 생략)");
            }
            printf("\n");
        }
    } else {
        // 일반적인 페이로드는 기존 방식으로 출력
        print_payload(payload, len);
    }
}

// 패킷 캡처시 호출되는 콜백 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    
    // 이더넷 헤더 정보 출력
    printf("\n=== Ethernet Header ===\n");
    printf("   Source MAC: ");
    print_mac_address(eth->ether_shost);
    printf("\n   Destination MAC: ");
    print_mac_address(eth->ether_dhost);
    printf("\n");
    
    // IP 패킷인지 확인 (0x0800은 IP 타입)
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        int ip_header_len = (ip->iph_ihl & 0x0f) * 4; // IP 헤더 길이 계산 (4바이트 단위)
        
        // IP 헤더 정보 출력
        printf("=== IP Header ===\n");
        printf("   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("   Destination IP: %s\n", inet_ntoa(ip->iph_destip));
        
        // TCP 프로토콜만 처리 (6은 TCP)
        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
            
            // TCP 헤더 정보 출력
            printf("=== TCP Header ===\n");
            printf("   Source Port: %d\n", ntohs(tcp->tcp_sport));
            printf("   Destination Port: %d\n", ntohs(tcp->tcp_dport));
            
            // TCP 헤더 길이 계산 (4바이트 단위)
            int tcp_header_len = TH_OFF(tcp) * 4;
            
            // 데이터(페이로드) 시작 위치 계산
            int payload_offset = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            
            // 페이로드 길이 계산
            int payload_length = ntohs(ip->iph_len) - (ip_header_len + tcp_header_len);
            
            // 페이로드가 있으면 출력
            if (payload_length > 0) {
                const u_char *payload = packet + payload_offset;
                
                // HTTP 메시지인지 확인하고 특별 처리
                if (ntohs(tcp->tcp_dport) == 80 || ntohs(tcp->tcp_sport) == 80) {
                    printf("   Protocol: HTTP\n");
                    print_http_message(payload, payload_length);
                } else {
                    print_payload(payload, payload_length);
                }
            } else {
                printf("   No Payload\n");
            }
        }
    }
    printf("--------------------------------------------------\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // TCP 패킷만 필터링
    bpf_u_int32 net;
    bpf_u_int32 mask;
    
    // 네트워크 장치
    char *dev = "enp0s3";
    printf("device: %s\n", dev);
    
    // 네트워크 장치 정보 가져오기
    net = 0;
    mask = 0;
    
    // 패킷 캡처 세션 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "패킷 캡처 세션을 열 수 없습니다: %s\n", errbuf);
        return 2;
    }
    
    // 필터 컴파일
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "필터를 컴파일할 수 없습니다: %s\n", pcap_geterr(handle));
        return 3;
    }
    
    // 필터 적용
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "필터를 적용할 수 없습니다: %s\n", pcap_geterr(handle));
        return 4;
    }
    
    printf("TCP 패킷 캡처 시작...\n");
    printf("(Ctrl+C를 눌러 종료)\n");
    
    // 패킷 캡처 루프 시작
    pcap_loop(handle, -1, got_packet, NULL);
    
    // 자원 해제
    pcap_freecode(&fp);
    pcap_close(handle);
    
    return 0;
}
