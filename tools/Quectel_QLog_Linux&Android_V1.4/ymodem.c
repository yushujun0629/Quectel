#include "qlog.h"

#include <sys/epoll.h>

#define SOH_PAYLOAD_LEN 128
#define STX_PAYLOAD_LEN 1024
#define YMODEM_CRC16(_buff, _len) ((_buff[_len - 2] << 8) | (_buff[_len - 1]))

struct FrameHdr
{
    uint8_t tag;
    uint8_t idx;
    uint8_t comp;
    uint8_t data[0];
};

enum
{
    SOH = 0x01,
    STX = 0x02,
    EOT = 0x04,
    ACK = 0x06,
    NAK = 0x15,
    CAN = 0x18,
    CNC = 0x43,
};

static uint64_t g_is_transfering = 0;
static uint64_t g_get_stop_tag = 0;
static uint64_t g_total_recvsz = 0;
static uint64_t g_current_fd = -1;
static uint64_t g_current_filesz = 0;
static uint64_t g_current_recvsz = 0;
static char g_current_filename[128];

static void show_msg(uint8_t *_msg, int _len, const char *prefix)
{
    char buff[2048] = {'\0'};
    int pos = 0;
    if (prefix)
        snprintf(buff, sizeof(buff), "%s(%d): ", prefix, _len);

    while (pos < _len)
    {
        snprintf(buff + strlen(buff), sizeof(buff) - strlen(buff), "%02X ", (int)_msg[pos]);
        pos++;
    }
    qlog_dbg("%s\n", buff);
}

#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif
int async_write(int ttyfd, uint8_t *buff, int len)
{
    struct epoll_event ev;
    struct epoll_event events[1];
    int ret = -1;

    if (len == 0)
        return 0;

    int epfd = epoll_create(1);
    if (epfd < 0)
    {
        qlog_dbg("%s epoll_create failed with code %d\n", __func__, epfd);
        return -1;
    }

    ev.events = EPOLLOUT | EPOLLRDHUP;
    ev.data.fd = ttyfd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, ttyfd, &ev);
    int num = epoll_wait(epfd, events, 1, -1);
    if (num > 0)
    {
        if (events[0].events & EPOLLOUT)
        {
            ret = write(ttyfd, buff, len);
            if (ret == len)
                ret = 0;
            else
                qlog_dbg("serial want write %d bytes actually write %d bytes\n", len, ret);
        }
        else
            qlog_dbg("epoll get unexpect event 0x%x\n", events[0].events);
    }
    else if (num == 0)
        qlog_dbg("epoll get timeout\n");
    else
        qlog_dbg("epoll_wait error errcode %d\n", errno);

    if (ret)
        show_msg(buff, len, ">>>");

    close(epfd);
    return ret;
}

int async_read(int ttyfd, uint8_t *buff, int len, int *actlen)
{
    struct epoll_event ev;
    struct epoll_event events[1];
    int ret = -1;
    int _actlen;
    int epfd;

    if (len == 0)
        return 0;

    epfd = epoll_create(1);
    if (epfd < 0)
    {
        qlog_dbg("%s epoll_create failed with code %d\n", __func__, epfd);
        return -1;
    }

    ev.events = EPOLLIN | EPOLLRDHUP;
    ev.data.fd = ttyfd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, ttyfd, &ev);
    int num = epoll_wait(epfd, events, 1, -1);
    if (num > 0)
    {
        if (events[0].events & EPOLLIN)
        {
            ret = read(ttyfd, buff, len);
            if (actlen)
                *actlen = ret;
            _actlen = ret;
            if (ret == len)
                ret = 0;
            else if (len == 3 && ret == 1 && buff[0] == EOT)
                ret = 0;
            else if (ret == 0)
            {
                qlog_dbg("serial read get 0 result, check whether tty port is valid\n");
                ret = -1;
            }
            else
                qlog_dbg("serial want read %d bytes actually read %d bytes\n", len, ret);
        }
        else
            qlog_dbg("epoll get unexpect event 0x%x\n", events[0].events);
    }
    else if (num == 0)
        qlog_dbg("epoll get timeout\n");
    else
        qlog_dbg("epoll_wait error errcode %d\n", errno);

    if (ret)
        show_msg(buff, _actlen, "<<<");

    close(epfd);
    return ret;
}

uint16_t calc_crc16(const uint8_t *buff, int sz)
{
    uint16_t crc = 0;
    int i;

    while (sz--)
    {
        crc = crc ^ *buff++ << 8;
        for (i = 0; i < 8; i++)
        {
            if (crc & 0x8000)
                crc = crc << 1 ^ 0x1021;
            else
                crc = crc << 1;
        }
    }
    return crc;
}

static void status_bar(int byte_recv, int byte_all)
{
    static int pos = 0;
    static int state = 0;

    if (byte_recv >= byte_all)
    {
        qlog_raw_log("status: %d/%d\n", byte_recv, byte_all);
        return;
    }

    if (!((++pos) % 3))
    {
        state++;
        switch (state % 4)
        {
        case 0:

            qlog_raw_log("status: -");
            break;
        case 1:
            qlog_raw_log("status: \\");
            break;
        case 2:
            qlog_raw_log("status: |");
            break;
        case 3:
            qlog_raw_log("status: /");
            break;
        default:
            break;
        }
    }
}

int finishup()
{
    qlog_dbg("recv %s finished\n", g_current_filename);
    qlog_dbg("expect %lu bytes, actually get %lu bytes\n", g_current_filesz, g_current_recvsz);
    close(g_current_fd);
    g_is_transfering = 0;
    g_current_recvsz = 0;
    g_current_filesz = 0;
    g_current_filename[0] = '\0';
    g_current_fd = -1;
    return 0;
}

int varify_rx_pkt(uint8_t *buff, int len)
{
    uint16_t crc_expt = YMODEM_CRC16(buff, len);
    uint16_t crc_real = calc_crc16(buff, len - 2);
    int ret = (crc_expt == crc_real);

    if (!ret)
        qlog_dbg("%s crc check failed, datalen %d, (real)0x%x != (expt)0x%x\n", __func__, len, crc_real, crc_expt);
    return ret;
}

int parser_hdr(uint8_t *buff, int len)
{
    int offset = 0;

    snprintf(g_current_filename, sizeof(g_current_filename), "%s", (const char *)(buff + offset));
    offset += strlen(g_current_filename) + 1;
    g_current_filesz = strtoul((const char *)(buff + offset), NULL, 10);
    g_current_recvsz = 0;
    g_is_transfering = 1;
    qlog_dbg("\n");
    qlog_dbg("prepare to recv file '%s' with size of %lu bytes\n", g_current_filename, g_current_filesz);
    g_current_fd = open(g_current_filename, O_WRONLY | O_NONBLOCK | O_CREAT);
    if (g_current_fd < 0)
        qlog_dbg("open %s failed with errcode %d\n", g_current_filename, errno);
    return (g_current_fd > 0) ? 0 : -1;
}

int save_data(uint8_t *buff, int len)
{
    int remain_len = g_current_filesz - g_current_recvsz;
    int data_len = (remain_len < len) ? remain_len : len;
    int ret;

    g_current_recvsz += data_len;
    g_total_recvsz += data_len;

    ret = write(g_current_fd, buff, len);
    if (ret != len)
        qlog_dbg("%s save data failed, want write %d bytes, actually write %d bytes\n", __func__, len, ret);
    status_bar(g_current_recvsz, g_current_filesz);
    return (ret == len) ? 0 : -1;
}

int is_stop_pkt(uint8_t *buff, int len)
{
    int ret;
    int pos = sizeof(struct FrameHdr);

    while (buff[pos] == 0 && pos < len)
        pos++;
    ret = (pos == len);

    return ret;
}

int asr_rx_trigger(int ttyfd)
{
    uint8_t buff[] = {CNC};
    int ret;

    ret = async_write(ttyfd, buff, 1);
    if (ret)
        qlog_dbg("%s returns with code %d\n", __func__, ret);
    return ret;
}

int asr_rx_ack(int ttyfd)
{
    uint8_t buff[] = {ACK};
    int ret;

    ret = async_write(ttyfd, buff, 1);
    if (ret)
        qlog_dbg("%s returns with code %d\n", __func__, ret);
    return ret;
}

int asr_rx_hdr(int ttyfd, int *length, struct FrameHdr *hdr)
{
    const int max_try = 5;
    int times = 0;
    int actlen;
    int nextlen;
    int ret;

    hdr->tag = 0;
    hdr->idx = 0;
    hdr->comp = 0;
    while (1)
    {
        ret = async_read(ttyfd, (uint8_t *)hdr, sizeof(struct FrameHdr), &actlen);
        if (hdr->tag == 0 && times <= max_try)
            continue;

        if (ret)
        {
            if (hdr->tag == EOT)
                break;
            qlog_dbg("%s async_read returns with code %d\n", __func__, ret);
            return ret;
        }
        else
            break;
    }

    switch (hdr->tag)
    {
    case STX:
        nextlen = STX_PAYLOAD_LEN + 2;
        ret = 0;
        break;

    case SOH:
        nextlen = SOH_PAYLOAD_LEN + 2;
        ret = 0;
        break;

    case EOT:
        nextlen = 0;
        ret = 0;
        break;

    default:
        qlog_dbg("%s error tag %d\n", __func__, hdr->tag);
        nextlen = 0;
        ret = -1;
    }

    if (length)
        *length = nextlen;
    return ret;
}

int asr_rx_data(int ttyfd, int length, struct FrameHdr *hdr)
{
    uint8_t buff[2048];
    int actlen;
    int ret;

    ret = async_read(ttyfd, buff, length, &actlen);
    if (ret)
    {
        qlog_dbg("%s async_read returns with code %d\n", __func__, ret);
        return ret;
    }

    if (length && !varify_rx_pkt(buff, actlen))
    {
        qlog_dbg("%s varify_rx_pkt failed\n", __func__);
        return -1;
    }

    switch (hdr->tag)
    {
    case STX:
        ret = save_data(buff, length - 2);
        break;
    case SOH:
        if (hdr->idx == 0 && is_stop_pkt(buff, length - 2))
        {
            g_get_stop_tag = 1;
            ret = 0;
        }
        else if (g_is_transfering)
        {
            ret = save_data(buff, length - 2);
        }
        else
        {
            ret = parser_hdr(buff, length - 2);
        }
        break;
    case EOT:
        ret = finishup();
        break;
    default:
        qlog_dbg("%s error tag %d\n", __func__, hdr->tag);
        ret = -1;
    }

    if (ret)
        qlog_dbg("%s returns with code %d\n", __func__, ret);
    return ret;
}

int asr_catch_dump(int ttyfd, const char *logfile_dir)
{
    struct FrameHdr hdr = {0, 0, 0};
    int ret;
    int length;

    qlog_dbg("try to catch dump with YMODEM protocol(not standard)\n");
    qlog_dbg("Windows platfrom can use \"Tera Term\" to do this job\n");
    qlog_dbg("try to catch dump, it will take several minutes\n");
    qlog_dbg("\n");
    qlog_dbg("try to swicth work dir to %s\n", logfile_dir);
    if (chdir(logfile_dir))
    {
        qlog_dbg("fail to switch dir, check your argument\n");
        return -1;
    }

    // if (cont_filename)
    // {
    //     snprintf(g_current_filename, sizeof(g_current_filename), "%s", cont_filename);
    //     g_current_filesz = 0xfffffff;
    //     g_current_recvsz = 0;
    //     g_is_transfering = 1;
    //     qlog_dbg("prepare to recv file '%s' with size of %lu bytes\n", g_current_filename, g_current_filesz);
    //     g_current_fd = open(g_current_filename, O_WRONLY | O_NONBLOCK | O_APPEND);
    //     if (g_current_fd < 0)
    //     {
    //         qlog_dbg("open %s failed with errcode %d\n", g_current_filename, errno);
    //         return (g_current_fd > 0) ? 0 : -1;
    //     }
    //     asr_rx_ack(ttyfd);
    //     goto RECV_DATA;
    // }

    while (1)
    {
        ret = asr_rx_trigger(ttyfd) ||
              asr_rx_hdr(ttyfd, &length, &hdr) ||
              asr_rx_data(ttyfd, length, &hdr) ||
              asr_rx_ack(ttyfd);
        if (g_get_stop_tag)
        {
            qlog_dbg("%s finish transfer\n", __func__);
            qlog_dbg("totally recv %ld bytes\n", g_total_recvsz);
            ret = 0;
            goto QUIT;
        }

        if (ret)
            goto QUIT;

        // RECV_DATA:
        while (1)
        {
            ret = asr_rx_hdr(ttyfd, &length, &hdr) ||
                  asr_rx_data(ttyfd, length, &hdr) ||
                  asr_rx_ack(ttyfd);
            if (ret)
                goto QUIT;

            if (hdr.tag == EOT)
                break;
        }
    }

QUIT:
    qlog_dbg("%s returns with code %d\n", __func__, ret);
    return ret;
}