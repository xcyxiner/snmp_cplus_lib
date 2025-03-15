#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_PORT "161"
#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_COMMUNITY "public"

#define RECV_BUFFER_SIZE 1024
#define SEND_BUFFER_SIZE 1024

// 跨协议标准
#define ASN1_SEQUENCE 0x30
#define ASN1_INTEGER 0x02
#define ASN1_OCTET_STRING 0x04
#define ASN1_OBJECT_ID 0x06

// 临时字段标识 7-8
#define ASN1_CONTEXT_SPECIFIC (0B10 << 6)
// 结构化 6
#define ASN1_CONSTRUCTED (0B01 << 5)

#define SNMP_VERSION_1 0
// GetRequest-PDU ::=
// [0]
//     IMPLICIT PDU
#define SNMP_GET_REQUEST ASN1_CONTEXT_SPECIFIC + ASN1_CONSTRUCTED + 0

// GetResponse-PDU ::=
//               [2]
//                   IMPLICIT PDU
#define SNMP_GET_RESPONSE ASN1_CONTEXT_SPECIFIC + ASN1_CONSTRUCTED + 2

#include <iostream>
// 系统描述OID (.1.3.6.1.2.1.1.5.0)
const unsigned char sysDescrOID[] = {0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00};
const char sysDescr[] = "Simple SNMP Agent v1.0";

// BER编码辅助函数
void encode_length(unsigned char **ptr, int length) {
    if (length < 0x80) {
        *(*ptr)++ = (unsigned char)length;
    } else {
        int bytes = 0;
        int temp = length;
        while (temp > 0) { temp >>= 8; bytes++; }
        *(*ptr)++ = (unsigned char)(0x80 | bytes);
        for (int i = bytes - 1; i >= 0; i--) {
            *(*ptr)++ = (unsigned char)((length >> (i * 8)) & 0xFF);
        }
    }
}
int build_snpm_response(const unsigned char *request, int req_len, unsigned char *response)
{
    unsigned char *ptr = response;
    int total_len = 0;

    *ptr++ = ASN1_SEQUENCE;
    unsigned char *len_ptr = ptr++;

    // version        -- version-1 for this RFC
    //                          INTEGER {
    //                              version-1(0)
    //                          },
    *ptr++ = ASN1_INTEGER;
    *ptr++ = 0x01;
    *ptr++ = SNMP_VERSION_1;

    // community      -- community name
    // OCTET STRING,
    *ptr++ = ASN1_OCTET_STRING;
    *ptr++ = (unsigned char)strlen(DEFAULT_COMMUNITY);
    memcpy(ptr, DEFAULT_COMMUNITY, strlen(DEFAULT_COMMUNITY));
    ptr += strlen(DEFAULT_COMMUNITY);

    // data skip

    // PDU
    *ptr++ = SNMP_GET_RESPONSE;
    unsigned char *pdu_len_ptr = ptr++;

    // request id
    *ptr++ = ASN1_INTEGER;
    if(request[16] == 0x02){
        *ptr++ = 0x02;
        *ptr++ = request[17];
        *ptr++ = request[18];
    }
    if(request[16] == 0x04){
        *ptr++ = 0x04;
        *ptr++ = request[17];
        *ptr++ = request[18];
        *ptr++ = request[19];
        *ptr++ = request[20];
    }

    // error-status      -- sometimes ignored
    //                       INTEGER {
    //                           noError(0),
    //                           tooBig(1),
    //                           noSuchName(2),
    //                           badValue(3),
    //                           readOnly(4),
    //                           genErr(5)
    //                       },
    *ptr++ = ASN1_INTEGER;
    *ptr++ = 0x01;
    *ptr++ = 0x00;

    // error-index       -- sometimes ignored
    // INTEGER,

    *ptr++ = ASN1_INTEGER;
    *ptr++ = 0x01;
    *ptr++ = 0x00;

    //  variable-bindings -- values are sometimes ignored
    //      VarBindList

    //     -- variable bindings

    //     VarBind ::=
    //             SEQUENCE {
    //                 name
    //                     ObjectName,

    //                 value
    //                     ObjectSyntax
    //             }

    //    VarBindList ::=
    //             SEQUENCE OF
    //                VarBind

    *ptr++ = ASN1_SEQUENCE;
    unsigned char *var_len_ptr = ptr++;

    // 单个变量绑定
    *ptr++ = ASN1_SEQUENCE; // SEQUENCE
    unsigned char *item_len_ptr = ptr++; // 项长度

    // OID
    *ptr++ = ASN1_OBJECT_ID;
    *ptr++ = sizeof(sysDescrOID);
    memcpy(ptr, sysDescrOID, sizeof(sysDescrOID));
    ptr += sizeof(sysDescrOID);

    // 值
    *ptr++ = 0x04; // OCTET STRING
    *ptr++ = (unsigned char)strlen(sysDescr);
    memcpy(ptr, sysDescr, strlen(sysDescr));
    ptr += strlen(sysDescr);

    // 回填长度
    int item_len = ptr - item_len_ptr - 1;
    encode_length(&item_len_ptr, item_len);

    int var_len = ptr - var_len_ptr - 1;
    encode_length(&var_len_ptr, var_len);

    int pdu_len = ptr - pdu_len_ptr - 1;
    encode_length(&pdu_len_ptr, pdu_len);

    total_len = ptr - len_ptr - 1;
    encode_length(&len_ptr, total_len);

    return ptr - response;
}
int main(void)
{
    WSADATA wsaData;
    SOCKET sockfd;
    struct addrinfo hints, *servinfo;
    int rv;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cout << "Error in WSAStartup" << WSAGetLastError() << std::endl;
        return 1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, DEFAULT_PORT, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo:%d\n", rv);
        WSACleanup();
        return 1;
    }

    if ((sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) == INVALID_SOCKET)
    {
        std::cout << "Error in socket" << WSAGetLastError() << std::endl;
        freeaddrinfo(servinfo);
        WSACleanup();
        return 1;
    }

    if (bind(sockfd, servinfo->ai_addr, (int)servinfo->ai_addrlen) == SOCKET_ERROR)
    {

        std::cout << "Error in bind" << WSAGetLastError() << std::endl;
        closesocket(sockfd);
        freeaddrinfo(servinfo);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(servinfo);

    std::cout << "Waiting for a client..." << std::endl;

    struct sockaddr_storage client_addr;
    int addr_len;
    unsigned char recv_buffer[RECV_BUFFER_SIZE];
    unsigned char send_buffer[SEND_BUFFER_SIZE];

    while (1)
    {
        addr_len = sizeof(client_addr);
        int numbytes = recvfrom(sockfd, (char *)recv_buffer, RECV_BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);

        if (numbytes == SOCKET_ERROR)
        {
            std::cout << "Error in recvfrom" << WSAGetLastError() << std::endl;
            continue;
        }

        int resp_len = build_snpm_response(recv_buffer, numbytes, send_buffer);
        if (resp_len > 0)
        {
            if (sendto(sockfd, (char *)send_buffer, resp_len, 0, (struct sockaddr *)&client_addr, addr_len) == SOCKET_ERROR)
            {
                std::cout << "Error in sendTo" << WSAGetLastError() << std::endl;
            }
        }
    }

    closesocket(sockfd);
    WSACleanup();

    return 0;
}