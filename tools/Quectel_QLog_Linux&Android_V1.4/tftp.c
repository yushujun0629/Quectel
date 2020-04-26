/******************************************************************************
  @file    tftp.c
  @brief   sahara protocol to catch mdm ram dump.

  DESCRIPTION
  QLog Tool for USB and PCIE of Quectel wireless cellular modules.

  INITIALIZATION AND SEQUENCING REQUIREMENTS
  None.

  ---------------------------------------------------------------------------
  Copyright (c) 2016 - 2020 Quectel Wireless Solution, Co., Ltd.  All Rights Reserved.
  Quectel Wireless Solution Proprietary and Confidential.
  ---------------------------------------------------------------------------
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "errno.h"
#include "poll.h"

extern unsigned qlog_msecs(void);
#define dbg(fmt, arg... ) do { unsigned msec = qlog_msecs();  printf("[%03d.%03d]" fmt,  msec/1000, msec%1000, ## arg);} while (0)

/* opcodes we support */
#define TFTP_RRQ   1
#define TFTP_WRQ   2
#define TFTP_DATA  3
#define TFTP_ACK   4
#define TFTP_ERROR 5
#define TFTP_OACK  6

#define TFTP_MAX_RETRY  3

struct tftp_packet{
	uint16_t cmd;
	union{
		uint16_t code;
		uint16_t block;
		// For a RRQ and WRQ TFTP packet
		char filename[2];
	};
	uint8_t data[512];
};

// Socket fd this client use.
static struct sockaddr_in tftp_server, tftp_sender;
static socklen_t  addr_len;
static struct tftp_packet *tx_pkt;

static int tftp_socket(const char *serv_ip) {
    int sock, reuse_addr = 1;
    
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {
        dbg("%s socket() errno: %d (%s)\n", __func__, errno, strerror(errno));
        return -1;
    }
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr,sizeof(reuse_addr));    

    tftp_server.sin_family = AF_INET;
    tftp_server.sin_port = htons(69);
    inet_pton(AF_INET, serv_ip, &(tftp_server.sin_addr.s_addr));
    addr_len = sizeof(struct sockaddr_in);

    return sock;
}

int tftp_write_request(const char *serv_ip, const char *filename, long tsize, long blksize) {
    struct tftp_packet rx_pkt;
    int wait_ack;
    int ret, sock, size;

    dbg("%s filename=%s, tsize=%ld, blksize=%ld\n", __func__, filename, tsize, blksize);
    
    if (tx_pkt == NULL) {
        tx_pkt = (struct tftp_packet *)malloc(4 + blksize);
        if (tx_pkt == NULL)
            return -1;
    }

    sock = tftp_socket(serv_ip);
        
    tx_pkt->cmd = htons(TFTP_WRQ);
    size = sprintf(tx_pkt->filename, "%s%c%s%c%s%c%ld%c%s%c%ld%c", filename, 0, "octet", 0, "blksize", 0, blksize, 0, "tsize", 0, tsize, 0);	

    for(wait_ack = 0; wait_ack < TFTP_MAX_RETRY; wait_ack++) {
        struct pollfd pollfd = {sock, POLLIN, 0};

        sendto(sock, tx_pkt, size + 2, 0, (struct sockaddr*)&tftp_server, sizeof(tftp_server));

        do  {   
            ret = poll(&pollfd, 1, 1200);
        } while ((ret < 0) && (errno == EINTR));

        if (pollfd.revents & POLLIN) {
            int r_size = recvfrom(sock, &rx_pkt, sizeof(struct tftp_packet), MSG_DONTWAIT, (struct sockaddr *)&tftp_sender, &addr_len);

            if(r_size >= 4 && rx_pkt.cmd == htons(TFTP_OACK)) {
                return sock;
            }
        }
        else {
            dbg("%s wait ack timeout, ret=%d, errno: %d (%s)\n", __func__, ret, errno, strerror(errno));
        }
    }
       
    return -1;
}

static int tftp_send_pkt(int sock, struct tftp_packet *tx_pkt, uint16_t block, long size) {
    struct tftp_packet rx_pkt;
    int r_size = 0;
    int wait_ack;
    int ret;

    tx_pkt->cmd = htons(TFTP_DATA);
    tx_pkt->block = htons(block);
		
    for (wait_ack = 0; wait_ack < TFTP_MAX_RETRY; wait_ack++) {
        struct pollfd pollfd = {sock, POLLIN, 0};

        sendto(sock, tx_pkt, size + 4, 0, (struct sockaddr*)&tftp_sender, addr_len);

        do  {   
            ret = poll(&pollfd, 1, 1200);
        } while ((ret < 0) && (errno == EINTR));

        if (pollfd.revents & POLLIN) {
            r_size = recvfrom(sock, &rx_pkt, sizeof(struct tftp_packet), MSG_DONTWAIT, (struct sockaddr *)&tftp_sender, &addr_len);

            if(r_size >= 4 && rx_pkt.cmd == htons(TFTP_ACK) && rx_pkt.block == htons(block)) {
                return size;
            }
        }
        else {
            dbg("%s wait ack timeout, block=%d, ret=%d, errno: %d (%s)\n", __func__, block, ret, errno, strerror(errno));
        }
    }
    
    return 0;
}

int tftp_send_data(int sock, void *tx_buf, uint16_t block, long size) {
    if (tx_buf && size > 0) {
        memcpy(tx_pkt->data, tx_buf, size);
    }

    return tftp_send_pkt(sock, tx_pkt, block, size);
}
