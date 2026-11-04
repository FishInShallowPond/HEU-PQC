#include "chip.h"
#include <stdio.h>
#include <string.h>

/* Optional transport-boundary tests: compile this file alone (do not also link
 * chip_win32.c) with -DLC_CHIP_TEST_SERIAL. Only Win32 COM calls are replaced;
 * the driver's real framing, key ownership, conversions and ops are exercised. */
#ifdef LC_CHIP_TEST_SERIAL
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdlib.h>
static HANDLE WINAPI fake_open(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
static BOOL WINAPI fake_get_state(HANDLE,LPDCB);
static BOOL WINAPI fake_set_state(HANDLE,LPDCB);
static BOOL WINAPI fake_timeouts(HANDLE,LPCOMMTIMEOUTS);
static BOOL WINAPI fake_setup(HANDLE,DWORD,DWORD);
static BOOL WINAPI fake_purge(HANDLE,DWORD);
static BOOL WINAPI fake_status(HANDLE,LPDWORD,LPCOMSTAT);
static BOOL WINAPI fake_write(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
static BOOL WINAPI fake_read(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
static BOOL WINAPI fake_cancel(HANDLE,LPOVERLAPPED);
static BOOL WINAPI fake_result(HANDLE,LPOVERLAPPED,LPDWORD,BOOL);
static BOOL WINAPI fake_close(HANDLE);
static void fake_free(void *);
#define CreateFileA fake_open
#define GetCommState fake_get_state
#define SetCommState fake_set_state
#define SetCommTimeouts fake_timeouts
#define SetupComm fake_setup
#define PurgeComm fake_purge
#define ClearCommError fake_status
#define WriteFile fake_write
#define ReadFile fake_read
#define CancelIoEx fake_cancel
#define GetOverlappedResult fake_result
#define CloseHandle fake_close
#define free fake_free
#include "../src/chip_win32.c"
#undef CreateFileA
#undef GetCommState
#undef SetCommState
#undef SetCommTimeouts
#undef SetupComm
#undef PurgeComm
#undef ClearCommError
#undef WriteFile
#undef ReadFile
#undef CancelIoEx
#undef GetOverlappedResult
#undef CloseHandle
#undef free

static struct {
    uint8_t rx[LC_FRAME_MAX],loaded_sk[2528],loaded_pk[1312];
    size_t rx_n,rx_at;
    unsigned writes,opens,cancels,reaps,closed,freed,logs,read_bytes;
    int profile,short_write,trailing,pending,cancelled,verify_result,bad_request,zero_free;
    int oversized,clock_reply,enable_reply;
    DCB state;
    COMMTIMEOUTS timeouts;
} serial_fixture;
#define FAKE_PORT ((HANDLE)(uintptr_t)0x1234u)

static void fake_reset(void)
{
    memset(&serial_fixture,0,sizeof serial_fixture);
    serial_fixture.zero_free=1;
}

static void fake_reply(uint8_t head,uint8_t opcode,size_t n,uint8_t fill,
                       uint8_t first,uint8_t last)
{
    serial_fixture.rx[0]=(uint8_t)(head|0x80u); serial_fixture.rx[1]=opcode;
    serial_fixture.rx[2]=(uint8_t)n; serial_fixture.rx[3]=(uint8_t)(n>>8);
    serial_fixture.rx[4]=(uint8_t)(n>>16);
    memset(serial_fixture.rx+5,fill,n);
    if(n) { serial_fixture.rx[5]=first; serial_fixture.rx[4+n]=last; }
    serial_fixture.rx_at=0; serial_fixture.rx_n=n+5;
    if(serial_fixture.oversized) {
        serial_fixture.rx[2]=0x88; serial_fixture.rx[3]=0x13;
        serial_fixture.rx[4]=0; serial_fixture.rx_n=5005;
    }
    if(serial_fixture.trailing) serial_fixture.rx[serial_fixture.rx_n++]=0xff;
}

static HANDLE WINAPI fake_open(LPCSTR name,DWORD access,DWORD share,
 LPSECURITY_ATTRIBUTES security,DWORD disposition,DWORD flags,HANDLE template_file)
{
    (void)security; (void)template_file;
    ++serial_fixture.opens;
    if(strcmp(name,"\\\\.\\COM17") || share || disposition!=OPEN_EXISTING ||
       access!=(GENERIC_READ|GENERIC_WRITE) || !(flags&FILE_FLAG_OVERLAPPED)) {
        SetLastError(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE;
    }
    return FAKE_PORT;
}
static BOOL WINAPI fake_get_state(HANDLE h,LPDCB state)
{ (void)h; memset(state,0xff,sizeof *state); state->DCBlength=sizeof *state; return TRUE; }
static BOOL WINAPI fake_set_state(HANDLE h,LPDCB state)
{ (void)h; serial_fixture.state=*state; return TRUE; }
static BOOL WINAPI fake_timeouts(HANDLE h,LPCOMMTIMEOUTS timeouts)
{ (void)h; serial_fixture.timeouts=*timeouts; return TRUE; }
static BOOL WINAPI fake_setup(HANDLE h,DWORD in,DWORD out)
{ (void)h; return in>=8192 && out>=8192; }
static BOOL WINAPI fake_purge(HANDLE h,DWORD flags)
{ (void)h; (void)flags; serial_fixture.rx_at=serial_fixture.rx_n=0; return TRUE; }
static BOOL WINAPI fake_status(HANDLE h,LPDWORD errors,LPCOMSTAT status)
{
    (void)h; *errors=0; memset(status,0,sizeof *status);
    status->cbInQue=(DWORD)(serial_fixture.rx_n-serial_fixture.rx_at);
    return TRUE;
}

static BOOL WINAPI fake_write(HANDLE h,LPCVOID data,DWORD count,
                              LPDWORD done,LPOVERLAPPED ov)
{
    static const uint8_t clock_command[]={
        1,6,16,0,0,0,0,0,16,8,0,0,0,0,0,255,0,0,0,0,0
    };
    const uint8_t *p=data;
    size_t n,sk_n,pk_n,i;
    uint8_t sk_fill;
    (void)h; (void)ov;
    ++serial_fixture.writes; *done=count;
    if(serial_fixture.short_write) { *done=count-1u; return TRUE; }
    if(count==sizeof clock_command && !memcmp(data,clock_command,sizeof clock_command)) {
        switch(serial_fixture.clock_reply) {
        case 1: fake_reply(1,6,1,0,1,1); break; /* framed alarm */
        case 2:
            memcpy(serial_fixture.rx,clock_command,sizeof clock_command);
            serial_fixture.rx_n=sizeof clock_command; break;
        case 3: fake_reply(1,6,1,0,0,0); break;
        case 4: fake_reply(1,6,1,0,2,2); break;
        default: break;
        }
        return TRUE;
    }
    if(count<5) goto bad;
    n=(size_t)p[2] | ((size_t)p[3]<<8) | ((size_t)p[4]<<16);
    if(n!=count-5u) goto bad;
    if(p[0]==1 && p[1]==3 && n==16) {
        if(serial_fixture.enable_reply)
            fake_reply(1,3,1,0,(uint8_t)(serial_fixture.enable_reply-1),
                       (uint8_t)(serial_fixture.enable_reply-1));
        else fake_reply(1,3,0,0,0,0);
        return TRUE;
    }
    if(p[0]!=2) goto bad;
    if(p[1]==0 && n==1 && (p[5]==0x71 || p[5]==0x11)) {
        serial_fixture.profile=p[5];
        memset(serial_fixture.loaded_sk,0,sizeof serial_fixture.loaded_sk);
        fake_reply(2,0,1,0,0,0); return TRUE;
    }
    sk_n=serial_fixture.profile==0x71?2528u:1632u;
    pk_n=serial_fixture.profile==0x71?1312u:800u;
    sk_fill=serial_fixture.profile==0x71?0xa7:0xd3;
    switch(p[1]) {
    case 1:
        if(n) goto bad;
        memset(serial_fixture.loaded_sk,sk_fill,sk_n);
        fake_reply(2,1,0,0,0,0); break;
    case 2:
        if(n) goto bad;
        fake_reply(2,2,pk_n,0x31,0x12,0x34); break;
    case 3:
        if(n) goto bad;
        fake_reply(2,3,sk_n,sk_fill,sk_fill,sk_fill); break;
    case 4:
        if(n!=pk_n) goto bad;
        memcpy(serial_fixture.loaded_pk,p+5,n);
        fake_reply(2,4,1,0,0,0); break;
    case 5:
        if(n!=sk_n) goto bad;
        for(i=0;i<n;++i) if(p[i+5]!=sk_fill) goto bad;
        memcpy(serial_fixture.loaded_sk,p+5,n);
        fake_reply(2,5,1,0,0,0); break;
    case 11:
        if(serial_fixture.profile!=0x71 || n!=40 ||
           serial_fixture.loaded_sk[0]!=0xa7) goto bad;
        for(i=0;i<7;++i) if(p[5+i]!=0) goto bad;
        for(i=0;i<33;++i) if(p[12+i]!=(uint8_t)(32u-i)) goto bad;
        fake_reply(2,11,2420,0x51,0x56,0x78); break;
    case 10:
        if(serial_fixture.profile!=0x71 || n!=2462 || p[5]!=0x74 || p[6]!=9 ||
           p[7]!=0x56 || p[2426]!=0x78 || serial_fixture.loaded_pk[0]!=0x12 ||
           serial_fixture.loaded_pk[1311]!=0x34) goto bad;
        for(i=0;i<7;++i) if(p[2427+i]!=0) goto bad;
        for(i=0;i<33;++i) if(p[2434+i]!=(uint8_t)(32u-i)) goto bad;
        fake_reply(2,10,1,0,(uint8_t)serial_fixture.verify_result,
                   (uint8_t)serial_fixture.verify_result); break;
    case 8:
        if(serial_fixture.profile!=0x11 || n || serial_fixture.loaded_pk[0]!=0x12 ||
           serial_fixture.loaded_pk[799]!=0x34) goto bad;
        fake_reply(2,8,800,0x11,0x19,0x49);
        serial_fixture.rx[5+767]=0x29;
        memset(serial_fixture.rx+5+768,0x33,32);
        serial_fixture.rx[5+768]=0x39; serial_fixture.rx[5+799]=0x49; break;
    case 9:
        if(serial_fixture.profile!=0x11 || n!=768 || p[5]!=0x19 || p[772]!=0x29 ||
           serial_fixture.loaded_sk[0]!=0xd3) goto bad;
        fake_reply(2,9,32,0x33,0x39,0x49); break;
    default: goto bad;
    }
    return TRUE;
bad:
    serial_fixture.bad_request=1; SetLastError(ERROR_INVALID_DATA); return FALSE;
}

static BOOL WINAPI fake_read(HANDLE h,LPVOID data,DWORD count,LPDWORD done,LPOVERLAPPED ov)
{
    size_t available=serial_fixture.rx_n-serial_fixture.rx_at;
    (void)h; (void)ov;
    *done=0;
    if(serial_fixture.pending) {
        serial_fixture.cancelled=1;
        SetLastError(ERROR_IO_PENDING); return FALSE;
    }
    /* Fragment every header and every payload to exercise exact reads. */
    if(count>3u) count=3u;
    if(count>available) count=(DWORD)available;
    memcpy(data,serial_fixture.rx+serial_fixture.rx_at,count);
    serial_fixture.rx_at+=count; *done=count; serial_fixture.read_bytes+=count;
    return TRUE;
}
static BOOL WINAPI fake_cancel(HANDLE h,LPOVERLAPPED ov)
{ (void)h; ++serial_fixture.cancels; return SetEvent(ov->hEvent); }
static BOOL WINAPI fake_result(HANDLE h,LPOVERLAPPED ov,LPDWORD done,BOOL wait)
{
    (void)h; (void)ov; (void)wait; *done=0;
    ++serial_fixture.reaps; SetLastError(ERROR_OPERATION_ABORTED); return FALSE;
}
static BOOL WINAPI fake_close(HANDLE h)
{
    if(h==FAKE_PORT) { ++serial_fixture.closed; return TRUE; }
    return CloseHandle(h);
}
static void fake_free(void *ptr)
{
    const uint8_t *p=ptr;
    size_t i;
    for(i=0;i<sizeof(hw_device);++i) if(p[i]) serial_fixture.zero_free=0;
    ++serial_fixture.freed; free(ptr);
}
static int fake_cancelled(void *ctx) { (void)ctx; return serial_fixture.cancelled; }
static void fake_log(void *ctx,const char *text)
{
    (void)ctx;
    if(!strstr(text,"tx_bytes=") || !strstr(text,"rx_bytes=") ||
       strstr(text,"A7A7") || strstr(text,"D3D3")) serial_fixture.bad_request=1;
    ++serial_fixture.logs;
}
static lc_device *fake_device(char *err)
{
    lc_device_config cfg;
    memset(&cfg,0,sizeof cfg);
    cfg.mode=LC_HARDWARE; cfg.port="COM17";
    cfg.hooks.cancelled=fake_cancelled; cfg.hooks.log=fake_log;
    return lc_hw_open(&cfg,err);
}
#endif

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); return 0; \
} } while (0)

static int test_frames(void)
{
    static const uint8_t want[] = {2,4,3,0,0,0x11,0,0xff};
    const uint8_t payload[] = {0x11,0,0xff};
    uint8_t out[32];
    memset(out,0xa5,sizeof out);
    CHECK(lc_hw_frame(2,4,payload,sizeof payload,out,sizeof out)==sizeof want);
    CHECK(memcmp(out,want,sizeof want)==0);
    CHECK(out[sizeof want]==0xa5);
    CHECK(lc_hw_frame(2,1,NULL,0,out,sizeof out)==5);
    CHECK(memcmp(out,"\x02\x01\x00\x00\x00",5)==0);
    CHECK(lc_hw_frame(2,4,payload,3,out,7)==0);
    CHECK(lc_hw_frame(2,4,NULL,1,out,sizeof out)==0);
    CHECK(lc_hw_frame(2,4,payload,3,NULL,sizeof out)==0);
    CHECK(lc_hw_frame(2,4,payload,(size_t)-1,out,sizeof out)==0);
    CHECK(lc_hw_frame(2,4,payload,LC_FRAME_MAX,out,sizeof out)==0);
    return 1;
}

static int test_responses(void)
{
    const uint8_t valid[] = {0x82,2,3,0,0,0x11,0,0xff};
    const uint8_t ack0[] = {0x82,1,0,0,0};
    const uint8_t ack1[] = {0x82,1,1,0,0,0};
    const uint8_t reject[] = {0x82,1,1,0,0,1};
    const uint8_t unknown[] = {0x82,1,1,0,0,2};
    const uint8_t alarm[] = {0x81,1,1,0,0,1};
    const uint8_t oversize[] = {0x82,2,0,0,1};
    const uint8_t trailing[] = {0x82,1,0,0,0,0};
    uint8_t out[16],bad[sizeof valid];
    size_t n=99;
    char err[LC_ERR_MAX]={0};
    CHECK(lc_hw_validate(2,2,valid,sizeof valid,3,0,out,sizeof out,&n,err));
    CHECK(n==3 && memcmp(out,valid+5,3)==0);
    CHECK(lc_hw_validate(2,1,ack0,sizeof ack0,(size_t)-1,1,NULL,0,&n,err));
    CHECK(n==0);
    CHECK(lc_hw_validate(2,1,ack1,sizeof ack1,(size_t)-1,1,out,sizeof out,&n,err));
    CHECK(n==1 && out[0]==0);
    CHECK(!lc_hw_validate(2,1,reject,sizeof reject,(size_t)-1,1,out,sizeof out,&n,err));
    CHECK(n==0 && err[0]!=0);
    CHECK(!lc_hw_validate(2,1,unknown,sizeof unknown,(size_t)-1,1,out,sizeof out,&n,err));
    CHECK(!lc_hw_validate(1,1,alarm,sizeof alarm,(size_t)-1,0,out,sizeof out,&n,err));
    CHECK(!lc_hw_validate(2,2,valid,4,3,0,out,sizeof out,&n,err));
    CHECK(!lc_hw_validate(2,2,valid,sizeof valid-1,3,0,out,sizeof out,&n,err));
    CHECK(!lc_hw_validate(2,2,valid,sizeof valid,4,0,out,sizeof out,&n,err));
    CHECK(!lc_hw_validate(2,2,valid,sizeof valid,3,0,out,2,&n,err));
    CHECK(!lc_hw_validate(2,2,valid,sizeof valid,3,0,NULL,sizeof out,&n,err));
    CHECK(!lc_hw_validate(2,2,NULL,sizeof valid,3,0,out,sizeof out,&n,err));
    CHECK(!lc_hw_validate(2,2,oversize,sizeof oversize,(size_t)-1,0,out,sizeof out,&n,err));
    CHECK(!lc_hw_validate(2,1,trailing,sizeof trailing,(size_t)-1,1,out,sizeof out,&n,err));
    memcpy(bad,valid,sizeof bad); bad[0]=0x81;
    CHECK(!lc_hw_validate(2,2,bad,sizeof bad,3,0,out,sizeof out,&n,err));
    memcpy(bad,valid,sizeof bad); bad[1]=3;
    CHECK(!lc_hw_validate(2,2,bad,sizeof bad,3,0,out,sizeof out,&n,err));
    memcpy(bad,valid,sizeof bad); bad[4]=1;
    CHECK(!lc_hw_validate(2,2,bad,sizeof bad,3,0,out,sizeof out,&n,err));
    CHECK(n==0);
    return 1;
}

static int test_messages(void)
{
    static const uint8_t want[40] = {
        0,0,0,0,0,0,0,
        32,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,
        15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
    };
    uint8_t message[1000],out[1007];
    size_t i;
    for(i=0;i<sizeof message;++i) message[i]=(uint8_t)i;
    memset(out,0xa5,sizeof out);
    CHECK(lc_hw_message(message,33,out,sizeof out)==40);
    CHECK(memcmp(out,want,sizeof want)==0 && out[40]==0xa5);
    CHECK(lc_hw_message(message,33,out,39)==0);
    CHECK(lc_hw_message(message,0,out,sizeof out)==0);
    CHECK(lc_hw_message(message,8,out,sizeof out)==0);
    CHECK(lc_hw_message(message,1000,out,sizeof out)==0);
    CHECK(lc_hw_message(message,1001,out,sizeof out)==0);
    CHECK(lc_hw_message(message,(size_t)-1,out,sizeof out)==0);
    CHECK(lc_hw_message(NULL,33,out,sizeof out)==0);
    CHECK(lc_hw_message(message,33,NULL,sizeof out)==0);
    CHECK(lc_hw_message(message,7,out,sizeof out)==14);
    CHECK(out[0]==0 && out[1]==6 && out[7]==0);
    for(i=8;i<14;++i) CHECK(out[i]==0);
    CHECK(lc_hw_message(message,999,out,sizeof out)==1006);
    return 1;
}

static int cancelled(void *ctx) { (void)ctx; return 1; }

static int test_open_errors(void)
{
    lc_device_config cfg;
    char err[LC_ERR_MAX]={0};
    memset(&cfg,0,sizeof cfg);
    cfg.mode=LC_HARDWARE;
    CHECK(lc_hw_open(NULL,err)==NULL && err[0]);
    CHECK(lc_hw_open(&cfg,err)==NULL);
    cfg.port="NUL";
    CHECK(lc_hw_open(&cfg,err)==NULL);
    cfg.port="COM0";
    CHECK(lc_hw_open(&cfg,err)==NULL);
    cfg.port="COM1"; cfg.hooks.cancelled=cancelled;
    CHECK(lc_hw_open(&cfg,err)==NULL);
    return 1;
}

#ifdef LC_CHIP_TEST_SERIAL
static int test_driver_ops(void)
{
    lc_device *d;
    uint8_t pk[1312],kem_pk[800],sig[2420],ct[768],key[32],dec[32],message[33];
    size_t pn=sizeof pk,kn=sizeof kem_pk,sn=sizeof sig,cn=sizeof ct,i;
    unsigned writes;
    char err[LC_ERR_MAX]={0};
    fake_reset(); d=fake_device(err); CHECK(d!=NULL);
    CHECK(d->mode==LC_HARDWARE);
    CHECK(serial_fixture.state.BaudRate==38580);
    CHECK(serial_fixture.state.ByteSize==8 && serial_fixture.state.Parity==NOPARITY &&
          serial_fixture.state.StopBits==ONESTOPBIT && serial_fixture.state.fBinary);
    CHECK(!serial_fixture.state.fOutxCtsFlow && !serial_fixture.state.fOutxDsrFlow &&
          !serial_fixture.state.fOutX && !serial_fixture.state.fInX && !serial_fixture.state.fNull);
    CHECK(serial_fixture.timeouts.ReadTotalTimeoutConstant==200 &&
          serial_fixture.timeouts.WriteTotalTimeoutConstant==20000);
    CHECK(d->ops->sign_keygen(d,pk,&pn,err));
    CHECK(pn==1312 && pk[0]==0x34 && pk[1311]==0x12 && pk[1]==0x31);
    CHECK(d->ops->kem_keygen(d,kem_pk,&kn,err));
    CHECK(kn==800 && kem_pk[0]==0x34 && kem_pk[799]==0x12);
    for(i=0;i<33;++i) message[i]=(uint8_t)i;
    CHECK(d->ops->sign(d,message,sig,&sn,err));
    CHECK(sn==2420 && sig[0]==0x78 && sig[2419]==0x56);
    CHECK(d->ops->verify(d,pk,pn,message,sig,sn,err));
    CHECK(d->ops->encaps(d,kem_pk,kn,ct,&cn,key,err));
    CHECK(cn==768 && ct[0]==0x29 && ct[767]==0x19 && ct[1]==0x11);
    CHECK(key[0]==0x49 && key[31]==0x39 && key[1]==0x33);
    CHECK(d->ops->decaps(d,ct,cn,dec,err));
    CHECK(memcmp(dec,key,32)==0);
    CHECK(d->ops->sign(d,message,sig,&sn,err));
    serial_fixture.verify_result=1;
    CHECK(!d->ops->verify(d,pk,pn,message,sig,sn,err));
    serial_fixture.verify_result=0;
    CHECK(d->ops->verify(d,pk,pn,message,sig,sn,err));
    writes=serial_fixture.writes;
    pn=1311; CHECK(!d->ops->sign_keygen(d,pk,&pn,err)); CHECK(pn==0);
    CHECK(!d->ops->verify(d,pk,1311,message,sig,sn,err));
    CHECK(serial_fixture.writes==writes);
    serial_fixture.verify_result=2;
    CHECK(!d->ops->verify(d,pk,1312,message,sig,sn,err));
    writes=serial_fixture.writes;
    CHECK(!d->ops->sign(d,message,sig,&sn,err));
    CHECK(serial_fixture.writes==writes);
    CHECK(!serial_fixture.bad_request && serial_fixture.logs);
    d->ops->close(d);
    CHECK(serial_fixture.closed==1 && serial_fixture.freed==1 && serial_fixture.zero_free);
    return 1;
}

static int test_driver_failures(void)
{
    lc_device *d;
    uint8_t pk[1312];
    size_t pn;
    unsigned writes;
    char err[LC_ERR_MAX]={0};
    fake_reset(); d=fake_device(err); CHECK(d!=NULL);
    writes=serial_fixture.writes; serial_fixture.short_write=1; pn=sizeof pk;
    CHECK(!d->ops->sign_keygen(d,pk,&pn,err));
    CHECK(pn==0 && serial_fixture.writes==writes+1);
    pn=sizeof pk; CHECK(!d->ops->sign_keygen(d,pk,&pn,err));
    CHECK(serial_fixture.writes==writes+1);
    d->ops->close(d); CHECK(serial_fixture.zero_free);
    fake_reset(); d=fake_device(err); CHECK(d!=NULL);
    serial_fixture.pending=1; pn=sizeof pk;
    CHECK(!d->ops->sign_keygen(d,pk,&pn,err));
    CHECK(serial_fixture.cancels==1 && serial_fixture.reaps==1);
    d->ops->close(d); CHECK(serial_fixture.zero_free);
    fake_reset(); d=fake_device(err); CHECK(d!=NULL);
    serial_fixture.trailing=1; pn=sizeof pk;
    CHECK(!d->ops->sign_keygen(d,pk,&pn,err));
    CHECK(pn==0);
    d->ops->close(d); CHECK(serial_fixture.zero_free);
    return 1;
}

static int test_receive_bound_and_clock(void)
{
    lc_device *d;
    uint8_t pk[1312];
    size_t pn=sizeof pk;
    unsigned read_bytes;
    char err[LC_ERR_MAX]={0};
    fake_reset(); serial_fixture.clock_reply=1;
    d=fake_device(err); CHECK(d==NULL);
    CHECK(strstr(err,"alarm")!=NULL && serial_fixture.writes==1);
    CHECK(serial_fixture.closed==1 && serial_fixture.zero_free);
    fake_reset(); serial_fixture.clock_reply=4;
    d=fake_device(err); CHECK(d==NULL);
    CHECK(serial_fixture.writes==1 && serial_fixture.zero_free);
    fake_reset(); serial_fixture.clock_reply=2;
    d=fake_device(err); CHECK(d!=NULL);
    d->ops->close(d); CHECK(serial_fixture.zero_free);
    fake_reset(); serial_fixture.clock_reply=3;
    d=fake_device(err); CHECK(d==NULL);
    CHECK(serial_fixture.writes==1 && serial_fixture.zero_free);
    fake_reset(); serial_fixture.enable_reply=3;
    d=fake_device(err); CHECK(d==NULL);
    CHECK(serial_fixture.writes==2 && serial_fixture.zero_free);
    fake_reset(); serial_fixture.enable_reply=1;
    d=fake_device(err); CHECK(d!=NULL);
    read_bytes=serial_fixture.read_bytes; serial_fixture.oversized=1;
    CHECK(!d->ops->sign_keygen(d,pk,&pn,err));
    CHECK(serial_fixture.read_bytes-read_bytes==5);
    d->ops->close(d); CHECK(serial_fixture.zero_free);
    return 1;
}
#endif

int main(void)
{
    char err[LC_ERR_MAX]={0};
    if(!test_frames() || !test_responses() || !test_messages() || !test_open_errors()) return 1;
#ifdef LC_CHIP_TEST_SERIAL
    if(!test_driver_ops() || !test_driver_failures() || !test_receive_bound_and_clock()) return 1;
#endif
    if(!lc_hw_selftest(err)) { fprintf(stderr,"selftest: %s\n",err); return 1; }
    printf("chip: %u checks passed (no physical COM device used)\n",checks);
    return 0;
}
