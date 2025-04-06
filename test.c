#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    
    // 사용 가능한 모든 네트워크 인터페이스 목록 가져오기
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "인터페이스 목록을 가져오는 데 실패했습니다: %s\n", errbuf);
        return 1;
    }
    
    // 사용 가능한 인터페이스 출력
    printf("사용 가능한 인터페이스 목록:\n");
    int i = 0;
    for (temp = interfaces; temp; temp = temp->next) {
        printf("%d. %s", ++i, temp->name);
        if (temp->description)
            printf(" - %s", temp->description);
        printf("\n");
    }
    
    // 첫 번째 인터페이스로 캡처 세션 열기
    if (interfaces != NULL) {
        pcap_t *handle;
        handle = pcap_open_live(interfaces->name, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "인터페이스 %s에서 패킷 캡처 세션을 열 수 없습니다: %s\n", 
                    interfaces->name, errbuf);
        } else {
            printf("인터페이스 %s에서 캡처 세션을 열었습니다.\n", interfaces->name);
            pcap_close(handle);
        }
    }
    
    pcap_freealldevs(interfaces);
    return 0;
}