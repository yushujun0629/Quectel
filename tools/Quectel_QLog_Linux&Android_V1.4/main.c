/******************************************************************************
  @file    ql-tty2tcp.c
  @brief   enter point.

  DESCRIPTION
  QLog Tool for USB and PCIE of Quectel wireless cellular modules.

  INITIALIZATION AND SEQUENCING REQUIREMENTS
  None.

  ---------------------------------------------------------------------------
  Copyright (c) 2016 - 2020 Quectel Wireless Solution, Co., Ltd.  All Rights Reserved.
  Quectel Wireless Solution Proprietary and Confidential.
  ---------------------------------------------------------------------------
******************************************************************************/
#include "qlog.h"
#include "getopt.h"

#define LOGFILE_SIZE_MIN (2*1024*1024)
#define LOGFILE_SIZE_MAX (512*1024*1024)
#define LOGFILE_SIZE_DEFAULT (128*1024*1024)
#define LOGFILE_NUM 512
static char s_logfile_List[LOGFILE_NUM][32];
static unsigned s_logfile_num = 0;
static unsigned qlog_exit_requested = 0;
int g_ttyport_or_usbfs = 0; // 1 for usbfs, 0 for tty
extern int asr_catch_dump(int ttyfd, const char *logfile_dir);

uint32_t qlog_le32 (uint32_t v32) {
    uint32_t tmp = v32;
    const int is_bigendian = 1;

    if ( (*(char*)&is_bigendian) == 0 ) {
        unsigned char *s = (unsigned char *)(&v32);
        unsigned char *d = (unsigned char *)(&tmp);
        d[0] = s[3];
        d[1] = s[2];
        d[2] = s[1];
        d[3] = s[0];
    }
    return tmp;
}

uint64_t qlog_le64(uint64_t v64) {
    const uint64_t is_bigendian = 1;
    uint64_t tmp = v64;
	
    if ((*(char*)&is_bigendian) == 0) {
        unsigned char *s = (unsigned char *)(&v64);
        unsigned char *d = (unsigned char *)(&tmp);
        d[0] = s[7];
        d[1] = s[6];
        d[2] = s[5];
        d[3] = s[4];
        d[4] = s[3];
        d[5] = s[2];
        d[6] = s[1];
        d[7] = s[0];
    }
    return tmp;
}

unsigned qlog_msecs(void) {
    static unsigned start = 0;
    unsigned now;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    now = (unsigned)ts.tv_sec*1000 + (unsigned)(ts.tv_nsec / 1000000);
    if (start == 0)
        start = now;
    return now - start;
}

static int get_value_from_file(const char *fname, int base)
{
    char buff[64] = {'\0'};

    int fd = open(fname, O_RDONLY);
    if (fd <= 0)
    {
        qlog_dbg("Fail to open %s,  errno: %d (%s)\n", fname, errno, strerror(errno));
        return -1;
    }
    read(fd, buff, sizeof(buff));
    close(fd);
    return strtoul(buff, NULL, base);
}

void qlog_get_vidpid_by_ttyport(const char *ttyport, int *idVendor, int *idProduct, int *bNumInterfaces) {
    char syspath[255];
    char sysport[64];
    int count;
    char *pchar = NULL;
    int vid, pid, ifnum;

    memset(idVendor, 0x00, 5);
    memset(idProduct, 0x00, 5);
    memset(bNumInterfaces, 0x00, 5);
    
    snprintf(sysport, sizeof(sysport), "/sys/class/tty/%s", &ttyport[strlen("/dev/")]);
    count = readlink(sysport, syspath, sizeof(syspath) - 1);
    if (count < strlen(":1.0/tty"))
        return;

    // ttyUSB0 -> ../../devices/soc0/soc/2100000.aips-bus/2184200.usb/ci_hdrc.1/usb1/1-1/1-1:1.0/ttyUSB0/tty/ttyUSB0
    pchar = strstr(syspath, ":1.0/tty"); //MDM
    if (pchar == NULL)
        pchar = strstr(syspath, ":1.2/tty"); //ASR

    if (pchar == NULL) {
        qlog_dbg("%s is not a usb-to-serial device?\n", ttyport);
        return;
    }

    *pchar = '\0';
    while (*pchar != '/')
        pchar--;

    strcpy(sysport, pchar + 1);
    
    snprintf(syspath, sizeof(syspath), "/sys/bus/usb/devices/%s/idVendor", sysport);
    vid = get_value_from_file(syspath, 16);
    if (idVendor)
        *idVendor = vid;

    snprintf(syspath, sizeof(syspath), "/sys/bus/usb/devices/%s/idProduct", sysport);
    pid = get_value_from_file(syspath, 16);
    if (idProduct)
        *idProduct = pid;

    snprintf(syspath, sizeof(syspath), "/sys/bus/usb/devices/%s/bNumInterfaces", sysport);
    ifnum = get_value_from_file(syspath, 10);
    if (bNumInterfaces)
        *bNumInterfaces = ifnum;

    qlog_dbg("%s idVendor=%x, idProduct=%x, bNumInterfaces=%d\n", __func__, vid, pid, ifnum);
}

static int get_vidpid_by_usbfs(char *usbfs_path, int *idVendor, int *idProduct, int *bNumInterfaces)
{
    int usbfsfd = -1;
    ssize_t desclength;
    unsigned char devdesc[1024] = {0};
    int vid = 0;
    int pid = 0;
    int ifnum = 0;

    if (!usbfs_path || usbfs_path[0] == '\0')
    {
        qlog_dbg("invalid usbfs device (NULL or empty)\n");
        return -1;
    }

    usbfsfd = open(usbfs_path, O_RDWR | O_NDELAY);
    if (usbfsfd < 0)
    {
        qlog_dbg("open %s failed, error=%d(%s)\n", usbfs_path, errno, strerror(errno));
        return -1;
    }

    desclength = read(usbfsfd, devdesc, sizeof(devdesc));
    if (desclength < sizeof(struct usb_device_descriptor))
    {
        qlog_dbg("error read, descriptor length(%ld) should be sizeof(usb_device_descriptor)=%ld\n",
                 desclength, sizeof(struct usb_device_descriptor));
        return -1;
    }

    struct usb_device_descriptor *device = (struct usb_device_descriptor *)devdesc;
    if (device->bLength == sizeof(struct usb_device_descriptor) && device->bDescriptorType == USB_DT_DEVICE)
    {
        if (device->idVendor == 0x2c7c)
        {
            vid = device->idVendor;
            pid = device->idProduct;
            if (idVendor)
                *idVendor = device->idVendor;
            if (idProduct)
                *idProduct = device->idProduct;

            struct usb_config_descriptor *config = (struct usb_config_descriptor *)(devdesc + device->bLength);
            if (config->bLength == sizeof(struct usb_config_descriptor) && config->bDescriptorType == USB_DT_CONFIG)
            {
                ifnum = config->bNumInterfaces;
                if (bNumInterfaces)
                    *bNumInterfaces = config->bNumInterfaces;
            }

            qlog_dbg("usbfs node = %s, usbfsfd = %d\n", usbfs_path, usbfsfd);
            qlog_dbg("%s: idVendor=%x, idProduct=%x, bNumInterfaces=%d\n", __func__, vid, pid, ifnum);
        }
        else
        {
            qlog_dbg("usbfs node = %s, usbfsfd = %d\n", usbfs_path, usbfsfd);
            qlog_dbg("%s: idVendor=%x, idProduct=%x, bNumInterfaces=%d\n", __func__, vid, pid, ifnum);
            qlog_dbg("is that right???\n");
        }
    }
    else
    {
        qlog_dbg ("device->bLength == sizeof(struct usb_device_descriptor) && device->bDescriptorType == USB_DT_DEVICE\n");
        return -1;
    }

    return usbfsfd;
}

int qlog_get_vidpid_by_usbfs(char *usbfs_path, int *idVendor, int *idProduct, int *bNumInterfaces)
{
    if (usbfs_path && usbfs_path[0] != '\0')
    { // user provide usbfs path
        return get_vidpid_by_usbfs(usbfs_path, idVendor, idProduct, bNumInterfaces);
    }
    else
    { // auto find usbfs path
        const char *usbfs_rootdir = "/dev/bus/usb";
        DIR *rootdir = NULL;
        DIR *subdir = NULL;
        char busdir[128];
        struct dirent *entptr = NULL;

        rootdir = opendir(usbfs_rootdir);
        if (rootdir == NULL) {
            qlog_dbg("opendir %s failed, errno = %d(%s)\n", usbfs_rootdir, errno, strerror(errno));
            return -1;
        }

        while ((entptr = readdir(rootdir)) != NULL) {
            if (!strcmp(entptr->d_name, ".") || !strcmp(entptr->d_name, ".."))
                continue;

            sprintf(busdir, "%s/%s", usbfs_rootdir, entptr->d_name);
            subdir = opendir(busdir);

            while ((entptr = readdir(subdir)) != NULL)  {
                if (!strcmp(entptr->d_name, ".") || !strcmp(entptr->d_name, ".."))
                    continue;

                sprintf(usbfs_path, "%s/%s", busdir, entptr->d_name);
                int usbfsfd = get_vidpid_by_usbfs(usbfs_path, idVendor, idProduct, bNumInterfaces);
                if (usbfsfd > 0)
                    return usbfsfd;
                close(usbfsfd);
            }
            closedir(subdir);
        }
        closedir(rootdir);
        return -1;
    }
}

void* qlog_usbfs_read(void *arg)
{
    struct usbdevfs_bulktransfer bulk;
    unsigned char pbuf[4096] = {0};
    int usbfsfd = ((int*)arg)[0];
    int pipefd = ((int*)arg)[1];
    int n = 0;

    bulk.ep = g_is_asr_chip? 0x84 : 0x81;
    bulk.len = 4096;
    bulk.data = (void *)pbuf;
    bulk.timeout = 0; // keep waiting

    while (1)
    {
        int nwrites = 0;
        int count = 0;

        do {
            n = ioctl(usbfsfd, USBDEVFS_BULK, &bulk);
        } while ((n < 0) && (errno == EINTR));

        if (n > 0) {
            // printf("urb nreads = %d\n", n);
            while (count < n) {
                do {
                    nwrites = write(pipefd, pbuf, n);
                } while ((nwrites == -1) && (errno == EINTR || errno == EAGAIN));

                count += nwrites;
            }
        }
    }

    return NULL;
}

void qlog_usbfs_write(int fd, const void *buf, size_t size)
{
    struct usbdevfs_urb bulk;
    struct usbdevfs_urb *urb = &bulk;
    int n = 0;

    memset(urb, 0, sizeof(struct usbdevfs_urb));
    urb->type = USBDEVFS_URB_TYPE_BULK;
    urb->endpoint = g_is_asr_chip? 0x03 : 0x1;
    urb->status = -1;
    urb->buffer = (void *)buf;
    urb->buffer_length = size;
    urb->usercontext = urb;
    urb->flags = 0;

    do {
        n = ioctl(fd, USBDEVFS_SUBMITURB, urb);
    } while ((n < 0) && (errno == EINTR));

    do {
        urb = NULL;
        n = ioctl(fd, USBDEVFS_REAPURB, &urb);
    } while ((n < 0) && (errno == EINTR));

    if (urb && urb->status == 0 && urb->actual_length) {
        // qlog_dbg("urb->actual_length = %u\n", urb->actual_length);
    }
}

static size_t ql_tty_read(int fd, void *buf, size_t size)
{
    size_t rc;
    
    rc = read(fd,buf,size);

    if (rc > 0) {
    	static size_t total_read = 0;
    	static unsigned long now_msec = 0;
    	unsigned long n = qlog_msecs();

    	if (now_msec == 0)
    		now_msec = qlog_msecs();
    	total_read += rc;
    	
    	if ((total_read >= (16*1024*1024)) || (n >= (now_msec + 5000))) {
    		qlog_dbg("recv: %zdM %zdK %zdB  in %ld msec\n", total_read/(1024*1024),
    			total_read/1024%1024,total_read%1024, n-now_msec);
    		now_msec = n;
    		total_read = 0;
    	}
    }
		
    return rc;
}

ssize_t qlog_poll_write(int fd, const void *buf, size_t size, unsigned timeout_msec) {
    ssize_t wc = 0;
    ssize_t nbytes;

    nbytes = write(fd, buf+wc, size-wc);

    if (nbytes <= 0) {
        if (errno != EAGAIN) {
            qlog_dbg("Fail to write fd = %d, errno : %d (%s)\n", fd, errno, strerror(errno));
            goto out;
        }
        else {
            nbytes = 0;
        }
    }

    wc += nbytes;

    while (wc < size) {
        int ret;
        struct pollfd pollfds[] = {{fd, POLLOUT, 0}};

        ret = poll(pollfds, 1, timeout_msec);

        if (ret <= 0) {
            qlog_dbg("Fail to poll fd = %d, errno : %d (%s)\n", fd, errno, strerror(errno));
            break;
        }

        if (pollfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            qlog_dbg("Fail to poll fd = %d, revents = %04x\n", fd, pollfds[0].revents);
            break;
        }

        if (pollfds[0].revents & (POLLOUT)) {
            nbytes = write(fd, buf+wc, size-wc);
            
            if (nbytes <= 0) {
                qlog_dbg("Fail to write fd = %d, errno : %d (%s)\n", fd, errno, strerror(errno));
                break;
            }
            wc += nbytes;
        }
    }

out:
    if (wc != size) {
        qlog_dbg("%s fd=%d, size=%zd, timeout=%d, wc=%zd\n", __func__, fd, size, timeout_msec, wc);
    }
    
    return (wc);
}

static int qlog_logfile_create(const char *logfile_dir, const char *logfile_suffix, unsigned logfile_seq) {
    int logfd;
    time_t ltime;
    char shortname[32];
    char filename[255+1];
    struct tm *currtime;

    //delete old logfile
    if (s_logfile_num && s_logfile_List[logfile_seq%s_logfile_num][0]) {
        sprintf(filename, "%s/%s.%s", logfile_dir, s_logfile_List[logfile_seq%s_logfile_num], logfile_suffix);
        if (access(filename, R_OK) == 0) {
            remove(filename);
        }
    }

    time(&ltime);
    currtime = localtime(&ltime);
    snprintf(shortname, sizeof(shortname), "%04d%02d%02d_%02d%02d%02d_%04d",
    	(currtime->tm_year+1900), (currtime->tm_mon+1), currtime->tm_mday,
    	currtime->tm_hour, currtime->tm_min, currtime->tm_sec, logfile_seq);
    sprintf(filename, "%s/%s.%s", logfile_dir, shortname, logfile_suffix);

    logfd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0444);
    if (logfd <= 0) {
        qlog_dbg("Fail to create new logfile! errno : %d (%s)\n", errno, strerror(errno));
    }

    qlog_dbg("%s %s logfd=%d\n", __func__, filename, logfd);

    if (s_logfile_num) {
        strcpy(s_logfile_List[logfile_seq%s_logfile_num], shortname);
    }

    return logfd;
}

static size_t qlog_logfile_save(int logfd, const void *buf, size_t size) {
    return qlog_poll_write(logfd, buf, size, 1000);
}

static int qlog_logfile_close(int logfd) {
    return close(logfd);
}

static void* qlog_logfile_init_filter_thread(void* arg) {
    void **thread_args = (void **)arg;
    qlog_ops_t *qlog_ops = (qlog_ops_t *)thread_args[0];
    int *ttyfd = (int *)thread_args[1];
    const char *filter_cfg =  ( const char *)thread_args[2];

    if (qlog_ops->init_filter)
        qlog_ops->init_filter(*ttyfd, filter_cfg);
        
    return NULL;
}

static int qlog_handle(int handlefd, const char *logfile_dir, size_t logfile_size, unsigned logfile_num, const char *filter_cfg) {
    ssize_t savelog_size = 0;
    void *rbuf;
    const size_t rbuf_size = (16*1024);
    static int logfd = -1;
    unsigned logfile_seq = 0;
    const char *logfile_suffix = g_is_asr_chip ? "sdl" : "qmdl";
    static qlog_ops_t qlog_ops;
    pthread_t thread_id1, thread_id2;
    pthread_attr_t thread_attr;
    const void *thread_args[3];
	int usbfs_thread_args[2];
    struct pollfd pollfds[1];
    int pipefd[2];

    pollfds[0].events = POLLIN;
    if (g_ttyport_or_usbfs == 1) {
        pipe(pipefd);
        pollfds[0].fd = pipefd[0];  // read pipe
    } else {
        pollfds[0].fd = handlefd;
    }

    if (logfile_dir[0] == '9' && atoi(logfile_dir) >= 9000) {
        filter_cfg = logfile_dir;
        qlog_ops = tty2tcp_qlog_ops;
    }
    else {
        qlog_ops = g_is_asr_chip ? asr_qlog_ops : mdm_qlog_ops;
        if (access(logfile_dir, F_OK) && errno == ENOENT)
            mkdir(logfile_dir, 0755);
    }

    if (!qlog_ops.logfile_create)
        qlog_ops.logfile_create = qlog_logfile_create;
    if (!qlog_ops.logfile_save)
        qlog_ops.logfile_save = qlog_logfile_save;
    if (!qlog_ops.logfile_close)
        qlog_ops.logfile_close = qlog_logfile_close;

    rbuf = malloc(rbuf_size);
    if (rbuf == NULL) {
          qlog_dbg("Fail to malloc rbuf_size=%zd, errno: %d (%s)\n", rbuf_size, errno, strerror(errno));
          return -1;
    }

    thread_args[0] = &qlog_ops;
    thread_args[1] = &handlefd;
    thread_args[2] = filter_cfg;
    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thread_id1, &thread_attr, qlog_logfile_init_filter_thread, (void*)thread_args);

	if (g_ttyport_or_usbfs == 1) {
        usbfs_thread_args[0] = handlefd;
        usbfs_thread_args[1] = pipefd[1];  // write pipe
        pthread_create(&thread_id2, &thread_attr, qlog_usbfs_read, (void *)usbfs_thread_args);
    }
	
    while(qlog_exit_requested == 0) {
        ssize_t rc, wc;
        int ret;

        ret = poll(pollfds, 1, -1);
        if (ret <= 0) {
            qlog_dbg("poll(handlefd) =%d, errno: %d (%s)\n", ret, errno, strerror(errno));
            break;
        }

        if (pollfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            qlog_dbg("handlefd revents = %04x\n", pollfds[0].revents);
            break;
        }

        if (pollfds[0].revents & (POLLIN)) {
            rc = ql_tty_read(pollfds[0].fd, rbuf, rbuf_size);
            
            if(rc > 0) {
                if (logfd == -1) {
                    logfd = qlog_ops.logfile_create(logfile_dir, logfile_suffix, logfile_seq);
                    if (logfd <= 0) {
                        break;
                    }
                    if (qlog_ops.logfile_init)
                        qlog_ops.logfile_init(logfd, logfile_seq);
                    logfile_seq++;
                }
                        
                wc = qlog_ops.logfile_save(logfd, rbuf, rc);
 
                if (wc != rc) {
                    qlog_dbg("savelog fail %zd/%zd, break\n", wc, rc);
                    break;
                }

                savelog_size += wc;

                if (savelog_size >= logfile_size) {
                    savelog_size = 0;
                    qlog_ops.logfile_close(logfd);
                    logfd = -1;
                }
            }
            else
            {
                qlog_dbg("ttyfd recv %zd Bytes. break\n", rc);
                break;
            }
        }
    }   

    if (logfd > 0)
        qlog_ops.logfile_close(logfd);
    free(rbuf);

    return 0;
}

static void ql_sigaction(int signal_num) {
    qlog_dbg("recv signal %d\n", signal_num);
    qlog_exit_requested = 1;
}

static void qlog_usage(const char *self, const char *dev) {
    qlog_dbg("Usage: %s -p <log port> -s <log save dir> -f filter_cfg -n <log file max num> -b <log file size MBytes>\n", self);
    qlog_dbg("Default: %s -p %s -s %s -n %d -b %d to save log to local disk\n",
        self, dev, ".", LOGFILE_NUM, LOGFILE_SIZE_DEFAULT/1024/1024);
    qlog_dbg("    -p    The port to catch log (default '/dev/ttyUSB0')\n");
    qlog_dbg("              For serial port: /dev/ttyUSBX\n");
    qlog_dbg("              For usbfs: /dev/bus/usb/bus_number/device_number\n");
    qlog_dbg("    -s    Dir to save log, default is '.' \n");
    qlog_dbg("          if set as '9000', QLog will run in TCP Server Mode, and can be connected with 'QPST/QWinLog/CATStudio'!\n");
    qlog_dbg("    -f    filter cfg for catch log, can be found in directory 'conf'. if not set this arg, will use default filter conf\n");
    qlog_dbg("          and UC200T&EC200T do not need filter cfg.\n");
    qlog_dbg("    -n    max num of log file to save, range is '0~512'. default is 0. 0 means no limit.\n");
    qlog_dbg("          or QLog will auto delete oldtest log file if exceed max num\n");
    qlog_dbg("    -m    max size of single log file, unit is MBytes, range is '2~512', default is 128\n");
	
    qlog_dbg("\nFor example: %s -p /dev/ttyUSB0 -w .\n", self);
}

struct arguments
{
    // arguments
    char device[256];
    char logdir[256];

    // configurations
    int logfile_num;
    int logfile_sz;
    const char *filter_cfg;

    // devices info
    int idVendor;
    int idProduct;
    int bNumInterfaces;

    // profiles
    int devfd;
};

static struct arguments *parser_args(int argc, char **argv)
{
    int opt;
    static struct arguments args = {
        .device = "/dev/ttyUSB0",
        .logdir = "qlog_files",
        .devfd = -1,
        .logfile_num = LOGFILE_NUM,
        .logfile_sz = LOGFILE_SIZE_DEFAULT,
    };

    optind = 1; //call by popen(), optind mayby is not 1
    while (-1 != (opt = getopt(argc, argv, "p:s:n:m:f:h")))
    {
        switch (opt)
        {
        case 'p':
            if (optarg[0] == 't') //ttyUSB0
                snprintf(args.device, sizeof(args.device), "/dev/%s", optarg);
            else if (optarg[0] == 'U') //USB0
                snprintf(args.device, sizeof(args.device), "/dev/tty%s", optarg);
            else if (optarg[0] == '/')
                snprintf(args.device, sizeof(args.device), "%s", optarg);
            else
            {
                qlog_dbg("unknow dev %s\n", optarg);
                goto error;
            }
            qlog_dbg("will use device: %s\n", args.device);
            break;
        case 's':
            snprintf(args.logdir, sizeof(args.logdir), "%s", optarg);
            qlog_dbg("will save log into dir: %s\n", args.logdir);
            break;
        case 'n':
            args.logfile_num = atoi(optarg);
            if (args.logfile_num < 0)
                args.logfile_num = 0;
            else if (args.logfile_num > LOGFILE_NUM)
                args.logfile_num = LOGFILE_NUM;
            s_logfile_num = args.logfile_num;
            break;
        case 'm':
            args.logfile_sz = atoi(optarg) * 1024 * 1024;
            if (args.logfile_sz < LOGFILE_SIZE_MIN)
                args.logfile_sz = LOGFILE_SIZE_MIN;
            else if (args.logfile_sz > LOGFILE_SIZE_MAX)
                args.logfile_sz = LOGFILE_SIZE_MAX;
            break;
        case 'f':
            args.filter_cfg = optarg;
            break;
        case 'h':
        default:
            qlog_usage(argv[0], args.device);
            goto error;
        }
    }

    qlog_dbg("will use filter file: %s\n", args.filter_cfg ? args.filter_cfg : "default filter");
    if (access(args.device, F_OK | R_OK))
    {
        qlog_dbg("oops! cannot access(F_OK|R_OK) %s\n", args.device);
        goto error;
    }
    return &args;
error:
    return NULL;
}

static int serial_open(const char *device)
{
    int ttyfd = open(device, O_RDWR | O_NDELAY | O_NOCTTY);
    if (ttyfd < 0)
    {
        qlog_dbg("Fail to open %s, errno : %d (%s)\n", device, errno, strerror(errno));
    }
    else
    {
        qlog_dbg("open %s ttyfd = %d\n", device, ttyfd);
        struct termios ios;
        memset(&ios, 0, sizeof(ios));
        tcgetattr(ttyfd, &ios);
        cfmakeraw(&ios);
        cfsetispeed(&ios, B115200);
        cfsetospeed(&ios, B115200);
        tcsetattr(ttyfd, TCSANOW, &ios);
    }
    return ttyfd;
}

static inline int drv_is_asr(int idProduct)
{
    if ((idProduct & 0xF000) == 0x6000) // ASR
        g_is_asr_chip = 1;
    return g_is_asr_chip;
}

struct usbfs_getdriver
{
    unsigned int interface;
    char driver[255 + 1];
};

struct usbfs_ioctl
{
    int ifno;       /* interface 0..N ; negative numbers reserved */
    int ioctl_code; /* MUST encode size + direction of data so the
			 * macros in <asm/ioctl.h> give correct values */
    void *data;     /* param buffer (in, or out) */
};

#define IOCTL_USBFS_DISCONNECT _IO('U', 22)
#define IOCTL_USBFS_CONNECT _IO('U', 23)

static int usbfs_is_kernel_driver_alive(int fd, int ifnum)
{
    struct usbfs_getdriver getdrv;
    getdrv.interface = ifnum;
    if (ioctl(fd, USBDEVFS_GETDRIVER, &getdrv) < 0)
    {
        qlog_dbg("%s ioctl USBDEVFS_GETDRIVER on interface %d failed, kernel driver may be inactive\n", __func__, ifnum);
        return 0;
    }
    qlog_dbg("%s find interface %d has match the driver %s\n", __func__, ifnum, getdrv.driver);
    return 1;
}

static void usbfs_detach_kernel_driver(int fd, int ifnum)
{
    struct usbfs_ioctl operate;
    operate.data = NULL;
    operate.ifno = ifnum;
    operate.ioctl_code = IOCTL_USBFS_DISCONNECT;
    if (ioctl(fd, USBDEVFS_IOCTL, &operate) < 0)
        qlog_dbg("%s detach kernel driver failed\n", __func__);
    else
        qlog_dbg("%s detach kernel driver success\n", __func__);
}

static int prepare(struct arguments *args)
{
    int ret;

    if (!strncmp(args->device, "/dev/bus/usb", strlen("/dev/bus/usb")))
    {
        g_ttyport_or_usbfs = 1;
    }
    else if (!strncmp(args->device, "/dev/tty", strlen("/dev/tty")))
    {
        g_ttyport_or_usbfs = 0;
    }
    else
    {
        qlog_dbg("check your '-p' arguments, it should look like '/dev/ttyUSBX' or '/dev/bus/usb/BUSX/DEVX'\n");
        return -1;
    }

    if (g_ttyport_or_usbfs)
    {
        args->devfd = qlog_get_vidpid_by_usbfs(args->device, &args->idVendor, &args->idProduct, &args->bNumInterfaces);
        if (args->devfd < 0)
        {
            qlog_dbg("qlog_get_vidpid_by_usbfs failed\n");
            goto error;
        }
        drv_is_asr(args->idProduct);
        
        int DMInterfaceNumber = 0;
        if (args->bNumInterfaces > 1)
            DMInterfaceNumber = (g_is_asr_chip ? 2 : 0);
        else
        {
            qlog_dbg("error: catching dump via usbfs currently is not supportted!!!\n");
            return -1;
        }

        if (usbfs_is_kernel_driver_alive(args->devfd, DMInterfaceNumber))
            usbfs_detach_kernel_driver(args->devfd, DMInterfaceNumber);

        ret = ioctl(args->devfd, USBDEVFS_CLAIMINTERFACE, &DMInterfaceNumber); // attach usbfs driver
        if (ret != 0)
        {
            qlog_dbg("ioctl USBDEVFS_CLAIMINTERFACE failed, errno = %d(%s)\n", errno, strerror(errno));
            goto error;
        }
    }
    else if (!access(args->device, F_OK))
    {
        if (!strcmp(args->device, "/dev/mhi_DIAG"))
        {
            args->idVendor = 0x2c7c;
            args->bNumInterfaces = 5; //log mode
            qlog_dbg("%s with vid 2c7c, bNumInterfaces 5, in log mode\n", args->device);
        }
        else if (!strcmp(args->device, "/dev/mhi_SAHARA"))
        {
            args->idVendor = 0x2c7c;
            args->bNumInterfaces = 1; //dump mode
            qlog_dbg("%s with vid 2c7c, bNumInterfaces 1, in dump mode\n", args->device);
        }
        else
        {
            qlog_get_vidpid_by_ttyport(args->device, &args->idVendor, &args->idProduct, &args->bNumInterfaces);
        }

        drv_is_asr(args->idProduct);
        args->devfd = serial_open(args->device);
        if (args->devfd < 0)
        {
            qlog_dbg("serial_open failed\n");
            goto error;
        }
    }
    else
    {
        qlog_dbg("cann't catch log, no ttyport and usbfs node!\n");
        goto error;
    }
    return 0;
error:
    close(args->devfd);
    return ret;
}

int main(int argc, char **argv)
{
    int ret = -1;

    struct arguments *args = parser_args(argc, argv);
    if (!args)
    {
        qlog_dbg("parser_args failed\n");
        goto error;
    }

    qlog_dbg("QLog Version: Quectel_QLog_Linux&Android_V1.4\n"); //when release, rename to V1.X
    signal(SIGTERM, ql_sigaction);
    signal(SIGHUP, ql_sigaction);
    signal(SIGINT, ql_sigaction);

    if (prepare(args) < 0)
    {
        qlog_dbg("arg do prepare failed\n");
        goto error;
    }

    qlog_dbg("Press CTRL+C to stop catch log.\n");
    if (args->bNumInterfaces == 1) {
        if (access(args->logdir, F_OK) && errno == ENOENT)
            mkdir(args->logdir, 0755);

        if (g_is_asr_chip)
        {
            qlog_dbg("catch dump for asr chipset\n");
            ret = asr_catch_dump(args->devfd, args->logdir);
        }
        else
        {
            qlog_dbg("catch dump for other chipset\n");
            ret = sahara_catch_dump(args->devfd, args->logdir, 1);
        }
    }
    else if (args->bNumInterfaces > 1) {
		if (g_ttyport_or_usbfs == 0)
            qlog_dbg("catch log via tty port\n");
        else
            qlog_dbg("catch log via usbfs\n");
        ret = qlog_handle(args->devfd, args->logdir, args->logfile_sz, args->logfile_num, args->filter_cfg);
    } 
    else {
        qlog_dbg("unknow state! quit!\n");
        goto error;
    }

error:
    if (args && args->devfd > 0)
    {
        if (g_ttyport_or_usbfs == 1)
        {
            int DMInterfaceNumber = (g_is_asr_chip ? 2 : 0);
            ioctl(args->devfd, USBDEVFS_RELEASEINTERFACE, &DMInterfaceNumber);
        }
        close(args->devfd);
    }

    return ret;
}