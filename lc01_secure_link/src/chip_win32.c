#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include "chip.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HW_ANY ((size_t)-1)
#define HW_SIG_PK 1312u
#define HW_SIG_SK 2528u
#define HW_SIG 2420u
#define HW_KEM_PK 800u
#define HW_KEM_SK 1632u
#define HW_CT 768u
#define HW_KEY 32u
/* This backend supports only the fixed Dilithium2 / Kyber512 wire profiles.
 * Largest frame is the 2528-byte signature SK plus its five-byte header. */
#define HW_WIRE_MAX 4096u

size_t lc_hw_frame(uint8_t head,uint8_t opcode,const uint8_t *payload,
                   size_t n,uint8_t *out,size_t cap)
{
    if(!out || (n && !payload) || n>0xffffffu ||
       n>LC_FRAME_MAX-5u || cap<5u || n>cap-5u) return 0;
    if(n) memmove(out+5,payload,n);
    out[0]=head; out[1]=opcode;
    out[2]=(uint8_t)n; out[3]=(uint8_t)(n>>8); out[4]=(uint8_t)(n>>16);
    return n+5u;
}

int lc_hw_validate(uint8_t head,uint8_t opcode,const uint8_t *frame,size_t n,
                   size_t expected,int ack,uint8_t *out,size_t cap,
                   size_t *out_n,char *err)
{
    size_t length;
    if(out_n) *out_n=0;
    if(!frame || n<5u || n>LC_FRAME_MAX)
        return lc_error(err,"LC01 invalid response frame size");
    length=(size_t)frame[2] | ((size_t)frame[3]<<8) | ((size_t)frame[4]<<16);
    if(length>LC_FRAME_MAX-5u || length!=n-5u)
        return lc_error(err,"LC01 response length mismatch");
    if(frame[0]==0x81 && frame[1]==opcode && length==1u && frame[5]==1)
        return lc_error(err,"LC01 chip alarm");
    if(frame[0]!=(uint8_t)(head|0x80u) || frame[1]!=opcode)
        return lc_error(err,"LC01 unexpected response type");
    if(expected!=HW_ANY && length!=expected)
        return lc_error(err,"LC01 unexpected response payload size");
    if(ack && !(length==0 || (length==1u && frame[5]==0)))
        return lc_error(err,"LC01 command rejected or unknown acknowledgement");
    if(length>cap || (length && !out))
        return lc_error(err,"LC01 response output buffer too small");
    if(length) memmove(out,frame+5,length);
    if(out_n) *out_n=length;
    return 1;
}

size_t lc_hw_message(const uint8_t *message,size_t n,uint8_t *out,size_t cap)
{
    uint8_t prepared[1007];
    size_t leading,i;
    if(!message || !out || n<1u || n>1000u || n%8u==0 || cap<n+7u) return 0;
    leading=(8u-n%8u)%8u;
    memset(prepared,0,n+7u);
    for(i=0;i<n;++i) prepared[leading+i]=message[n-1u-i];
    memcpy(out,prepared,n+7u);
    lc_zero(prepared,sizeof prepared);
    return n+7u;
}

int lc_hw_selftest(char *err)
{
    static const uint8_t want[] = {2,0,1,0,0,0x71};
    static const uint8_t ack[] = {0x82,0,1,0,0,0};
    static const uint8_t bad[] = {0x82,0,1,0,0,2};
    uint8_t out[40],message[33],selector=0x71;
    char local[LC_ERR_MAX];
    size_t n,i;
    if(lc_hw_frame(2,0,&selector,1,out,sizeof out)!=sizeof want ||
       memcmp(out,want,sizeof want)!=0)
        return lc_error(err,"LC01 frame self-test failed");
    if(!lc_hw_validate(2,0,ack,sizeof ack,HW_ANY,1,out,sizeof out,&n,local) ||
       n!=1 || out[0]!=0 ||
       lc_hw_validate(2,0,bad,sizeof bad,HW_ANY,1,out,sizeof out,&n,local))
        return lc_error(err,"LC01 response self-test failed");
    for(i=0;i<sizeof message;++i) message[i]=(uint8_t)i;
    if(lc_hw_message(message,sizeof message,out,sizeof out)!=40)
        return lc_error(err,"LC01 message self-test failed");
    for(i=0;i<7;++i) if(out[i]!=0) return lc_error(err,"LC01 message padding failed");
    for(i=0;i<33;++i) if(out[i+7]!=(uint8_t)(32u-i))
        return lc_error(err,"LC01 message reversal failed");
    return 1;
}

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

typedef struct {
    lc_device base;
    HANDLE port;
    CRITICAL_SECTION lock;
    lc_hooks hooks;
    DWORD timeout_ms,interval_ms;
    ULONGLONG last_end;
    int has_last_end,profile,failed;
    int have_sign,have_kem;
    /* Only these backend-owned arrays retain private keys across profiles. */
    uint8_t sign_sk[HW_SIG_SK],kem_sk[HW_KEM_SK];
} hw_device;

static int hw_cancelled(hw_device *d,char *err)
{
    if(d->hooks.cancelled && d->hooks.cancelled(d->hooks.ctx))
        return lc_error(err,"LC01 operation cancelled"),1;
    return 0;
}

static int hw_winerror(char *err,const char *action)
{
    DWORD code=GetLastError();
    char message[LC_ERR_MAX];
    (void)snprintf(message,sizeof message,"LC01 %s failed (Win32 %lu)",action,(unsigned long)code);
    return lc_error(err,message);
}

static int hw_lock(hw_device *d,char *err)
{
    for(;;) {
        if(hw_cancelled(d,err)) return 0;
        if(TryEnterCriticalSection(&d->lock)) break;
        Sleep(5);
    }
    if(d->failed) {
        LeaveCriticalSection(&d->lock);
        return lc_error(err,"LC01 state uncertain; close and reopen the device");
    }
    return 1;
}

static int hw_deadline(hw_device *d,ULONGLONG deadline,char *err)
{
    if(hw_cancelled(d,err)) return 0;
    if(GetTickCount64()>=deadline) return lc_error(err,"LC01 command timed out");
    return 1;
}

static int hw_sleep_until(hw_device *d,ULONGLONG until,char *err)
{
    ULONGLONG now;
    while((now=GetTickCount64())<until) {
        if(hw_cancelled(d,err)) return 0;
        Sleep((DWORD)((until-now)>5u ? 5u : until-now));
    }
    return !hw_cancelled(d,err);
}

/* Each OVERLAPPED and its buffer stay alive until completion, including cancel.
 * A conforming serial driver must complete cancellation; never free pending IO. */
static int hw_io(hw_device *d,int writing,uint8_t *buffer,DWORD n,
                 DWORD *done,ULONGLONG deadline,char *err)
{
    OVERLAPPED ov;
    BOOL immediate;
    int ok=0;
    *done=0;
    if(!hw_deadline(d,deadline,err)) return 0;
    memset(&ov,0,sizeof ov);
    ov.hEvent=CreateEventA(NULL,TRUE,FALSE,NULL);
    if(!ov.hEvent) return hw_winerror(err,"create I/O event");
    if(writing) immediate=WriteFile(d->port,buffer,n,done,&ov);
    else immediate=ReadFile(d->port,buffer,n,done,&ov);
    if(immediate) ok=hw_deadline(d,deadline,err);
    else if(GetLastError()!=ERROR_IO_PENDING) (void)hw_winerror(err,writing?"write":"read");
    else {
        for(;;) {
            DWORD wait_result;
            ULONGLONG remaining;
            if(!hw_deadline(d,deadline,err)) break;
            remaining=deadline-GetTickCount64();
            /* Guard subtraction against the clock advancing between checks. */
            if(remaining>(ULONGLONG)d->timeout_ms) remaining=0;
            wait_result=WaitForSingleObject(ov.hEvent,(DWORD)(remaining>20u?20u:remaining));
            if(wait_result==WAIT_OBJECT_0) {
                if(GetOverlappedResult(d->port,&ov,done,FALSE)) ok=hw_deadline(d,deadline,err);
                else (void)hw_winerror(err,writing?"write completion":"read completion");
                break;
            }
            if(wait_result!=WAIT_TIMEOUT) { (void)hw_winerror(err,"I/O wait"); break; }
        }
        if(!ok) {
            DWORD ignored;
            (void)CancelIoEx(d->port,&ov);
            /* Cancellation can race successful completion. In either case reap it. */
            (void)GetOverlappedResult(d->port,&ov,&ignored,TRUE);
        }
    }
    (void)CloseHandle(ov.hEvent);
    return ok;
}

static int hw_status(hw_device *d,COMSTAT *status,char *err)
{
    DWORD errors=0;
    memset(status,0,sizeof *status);
    if(!ClearCommError(d->port,&errors,status)) return hw_winerror(err,"serial status");
    if(errors) return lc_error(err,"LC01 serial framing, parity, or overrun error");
    return 1;
}

static int hw_no_pending(hw_device *d,char *err)
{
    COMSTAT status;
    if(!hw_status(d,&status,err)) return 0;
    if(status.cbInQue) return lc_error(err,"LC01 unsolicited or trailing serial bytes");
    return 1;
}

static int hw_exact(hw_device *d,uint8_t *buffer,size_t n,ULONGLONG deadline,char *err)
{
    size_t offset=0;
    while(offset<n) {
        DWORD got=0;
        if(!hw_io(d,0,buffer+offset,(DWORD)(n-offset),&got,deadline,err)) return 0;
        if(got>n-offset) return lc_error(err,"LC01 invalid serial read count");
        offset+=got;
    }
    return 1;
}

/* Clock enable is the sole unframed exchange and permits an optional echo. */
static int hw_exchange(hw_device *d,const uint8_t *tx,size_t tx_n,int clock,
                       uint8_t *rx,size_t rx_cap,size_t *rx_n,char *err)
{
    ULONGLONG deadline,start=GetTickCount64();
    DWORD sent=0;
    size_t length=0,total_rx=0;
    int ok=0;
    COMSTAT status;
    char metadata[160];
    *rx_n=0;
    if(!tx || tx_n<5u || tx_n>HW_WIRE_MAX || !rx || rx_cap<5u)
        return lc_error(err,"LC01 invalid exchange buffer capacity");
    if(d->has_last_end && !hw_sleep_until(d,d->last_end+d->interval_ms,err)) return 0;
    if(!hw_no_pending(d,err)) { d->failed=1; return 0; }
    deadline=GetTickCount64()+d->timeout_ms;
    if(!hw_io(d,1,(uint8_t *)tx,(DWORD)tx_n,&sent,deadline,err)) goto finish;
    if(sent!=tx_n) { (void)lc_error(err,"LC01 short serial write; command not retried"); goto finish; }
    do {
        if(!hw_deadline(d,deadline,err) || !hw_status(d,&status,err)) goto finish;
        if(status.cbOutQue && !hw_sleep_until(d,GetTickCount64()+2u,err)) goto finish;
    } while(status.cbOutQue);
    if(clock) {
        ULONGLONG idle=GetTickCount64()+200u;
        if(idle>deadline) idle=deadline;
        while(GetTickCount64()<idle) {
            if(!hw_deadline(d,deadline,err) || !hw_status(d,&status,err)) goto finish;
            if(status.cbInQue) {
                DWORD got=0;
                if(status.cbInQue>rx_cap-total_rx) {
                    (void)lc_error(err,"LC01 excessive clock echo"); goto finish;
                }
                if(!hw_io(d,0,rx+total_rx,status.cbInQue,&got,deadline,err)) goto finish;
                if(got>rx_cap-total_rx) { (void)lc_error(err,"LC01 invalid clock read count"); goto finish; }
                total_rx+=got;
                if(got) { idle=GetTickCount64()+80u; if(idle>deadline) idle=deadline; }
            }
            if(!hw_sleep_until(d,GetTickCount64()+5u,err)) goto finish;
        }
        if(!hw_deadline(d,deadline,err)) goto finish;
        if(total_rx && !(total_rx==tx_n && memcmp(rx,tx,tx_n)==0)) {
            /* Recognize the chip's explicit alarm; never silently swallow it.
             * Clock enable has no framed ACK contract: only its exact echo is
             * accepted, even when some other frame looks like a success ACK. */
            if(total_rx==6u && rx[0]==0x81 && rx[1]==6 &&
               rx[2]==1 && rx[3]==0 && rx[4]==0 && rx[5]==1)
                (void)lc_error(err,"LC01 clock chip alarm");
            else (void)lc_error(err,"LC01 unexpected clock response (not an exact echo)");
            goto finish;
        }
    } else {
        if(!hw_exact(d,rx,5,deadline,err)) goto finish;
        length=(size_t)rx[2] | ((size_t)rx[3]<<8) | ((size_t)rx[4]<<16);
        if(length>HW_WIRE_MAX-5u || length>rx_cap-5u) {
            (void)lc_error(err,"LC01 response exceeds fixed-profile buffer capacity"); goto finish;
        }
        if(!hw_exact(d,rx+5,length,deadline,err) || !hw_no_pending(d,err)) goto finish;
        *rx_n=length+5u;
        total_rx=*rx_n;
    }
    ok=1;
finish:
    d->last_end=GetTickCount64(); d->has_last_end=1;
    if(!ok) { d->failed=1; d->profile=0; }
    if(d->hooks.log) {
        (void)snprintf(metadata,sizeof metadata,
            "LC01 opcode=%u tx_bytes=%lu rx_bytes=%lu elapsed_ms=%llu transport=%s",
            (unsigned)tx[1],(unsigned long)sent,(unsigned long)total_rx,
            (unsigned long long)(d->last_end-start),ok?"ok":"failed");
        d->hooks.log(d->hooks.ctx,metadata);
    }
    return ok;
}

static int hw_command(hw_device *d,uint8_t head,uint8_t opcode,
                      const uint8_t *payload,size_t n,size_t expected,int ack,
                      uint8_t *out,size_t cap,size_t *out_n,char *err)
{
    uint8_t tx[HW_WIRE_MAX],rx[HW_WIRE_MAX];
    size_t tx_n,rx_n=0;
    int ok;
    tx_n=lc_hw_frame(head,opcode,payload,n,tx,sizeof tx);
    if(!tx_n) return lc_error(err,"LC01 invalid command size");
    ok=hw_exchange(d,tx,tx_n,0,rx,sizeof rx,&rx_n,err);
    if(ok) {
        ok=lc_hw_validate(head,opcode,rx,rx_n,expected,ack,out,cap,out_n,err);
        if(!ok) { d->failed=1; d->profile=0; }
    }
    lc_zero(tx,sizeof tx); lc_zero(rx,sizeof rx);
    return ok;
}

static int hw_ack(hw_device *d,uint8_t opcode,const uint8_t *payload,size_t n,char *err)
{
    uint8_t ack[1];
    return hw_command(d,2,opcode,payload,n,HW_ANY,1,ack,sizeof ack,NULL,err);
}

static int hw_profile(hw_device *d,int profile,char *err)
{
    uint8_t selector=(uint8_t)(profile==1?0x71:0x11);
    if(d->profile==profile) return 1;
    if(!hw_ack(d,0,&selector,1,err)) return 0;
    d->profile=profile;
    return 1;
}

static void hw_reverse(uint8_t *out,const uint8_t *in,size_t n)
{
    size_t i;
    for(i=0;i<n;++i) out[i]=in[n-1u-i];
}

static int hw_capacity(uint8_t *out,size_t *n,size_t required,char *err)
{
    size_t cap=n?*n:0;
    if(n) *n=0;
    if(!out || !n || cap<required) return lc_error(err,"LC01 output buffer too small");
    return 1;
}

static int hw_keygen(lc_device *base,int sign,uint8_t *pk,size_t *pn,char *err)
{
    hw_device *d=(hw_device *)base;
    uint8_t raw_pk[HW_SIG_PK];
    uint8_t *sk=sign?d->sign_sk:d->kem_sk;
    size_t pk_n=sign?HW_SIG_PK:HW_KEM_PK,sk_n=sign?HW_SIG_SK:HW_KEM_SK;
    int *have=sign?&d->have_sign:&d->have_kem;
    int ok=0;
    if(!hw_capacity(pk,pn,pk_n,err) || !hw_lock(d,err)) return 0;
    *have=0; lc_zero(sk,sk_n);
    if(!hw_profile(d,sign?1:2,err) || !hw_ack(d,1,NULL,0,err) ||
       !hw_command(d,2,2,NULL,0,pk_n,0,raw_pk,sizeof raw_pk,NULL,err) ||
       !hw_command(d,2,3,NULL,0,sk_n,0,sk,sk_n,NULL,err)) goto finish;
    hw_reverse(pk,raw_pk,pk_n); *pn=pk_n; *have=1; ok=1;
finish:
    if(!ok) lc_zero(sk,sk_n);
    lc_zero(raw_pk,sizeof raw_pk);
    LeaveCriticalSection(&d->lock);
    return ok;
}

static int hw_sign_keygen(lc_device *d,uint8_t *pk,size_t *pn,char *err)
{ return hw_keygen(d,1,pk,pn,err); }
static int hw_kem_keygen(lc_device *d,uint8_t *pk,size_t *pn,char *err)
{ return hw_keygen(d,0,pk,pn,err); }

static int hw_sign(lc_device *base,const uint8_t *message,uint8_t *sig,size_t *sn,char *err)
{
    hw_device *d=(hw_device *)base;
    uint8_t prepared[40],raw[HW_SIG];
    int ok=0;
    if(!hw_capacity(sig,sn,HW_SIG,err)) return 0;
    if(!lc_hw_message(message,33,prepared,sizeof prepared)) return lc_error(err,"LC01 invalid signing message");
    if(!hw_lock(d,err)) { lc_zero(prepared,sizeof prepared); return 0; }
    if(!d->have_sign) { (void)lc_error(err,"LC01 signing key not generated"); goto finish; }
    if(!hw_profile(d,1,err) || !hw_ack(d,5,d->sign_sk,HW_SIG_SK,err) ||
       !hw_command(d,2,11,prepared,sizeof prepared,HW_SIG,0,raw,sizeof raw,NULL,err)) goto finish;
    hw_reverse(sig,raw,HW_SIG); *sn=HW_SIG; ok=1;
finish:
    lc_zero(prepared,sizeof prepared); lc_zero(raw,sizeof raw);
    LeaveCriticalSection(&d->lock);
    return ok;
}

static int hw_verify(lc_device *base,const uint8_t *pk,size_t pn,const uint8_t *message,
                     const uint8_t *sig,size_t sn,char *err)
{
    hw_device *d=(hw_device *)base;
    uint8_t raw_pk[HW_SIG_PK],payload[2u+HW_SIG+40u],result=0;
    int ok=0;
    if(!pk || pn!=HW_SIG_PK || !sig || sn!=HW_SIG || !message)
        return lc_error(err,"LC01 invalid verification field size");
    payload[0]=(uint8_t)HW_SIG; payload[1]=(uint8_t)(HW_SIG>>8);
    hw_reverse(payload+2,sig,HW_SIG);
    (void)lc_hw_message(message,33,payload+2+HW_SIG,40);
    hw_reverse(raw_pk,pk,HW_SIG_PK);
    if(!hw_lock(d,err)) goto cleanup;
    if(!hw_profile(d,1,err) || !hw_ack(d,4,raw_pk,sizeof raw_pk,err) ||
       !hw_command(d,2,10,payload,sizeof payload,1,0,&result,1,NULL,err)) goto finish;
    if(result>1) {
        d->failed=1;
        (void)lc_error(err,"LC01 unknown verification return code");
    } else if(result==1) (void)lc_error(err,"LC01 signature invalid");
    else ok=1;
finish:
    LeaveCriticalSection(&d->lock);
cleanup:
    lc_zero(raw_pk,sizeof raw_pk); lc_zero(payload,sizeof payload);
    return ok;
}

static int hw_encaps(lc_device *base,const uint8_t *pk,size_t pn,
                     uint8_t *ct,size_t *cn,uint8_t *key,char *err)
{
    hw_device *d=(hw_device *)base;
    uint8_t raw_pk[HW_KEM_PK],result[HW_CT+HW_KEY];
    int ok=0;
    if(key) lc_zero(key,HW_KEY);
    if(!hw_capacity(ct,cn,HW_CT,err)) return 0;
    if(!pk || pn!=HW_KEM_PK || !key) return lc_error(err,"LC01 invalid encapsulation field size");
    hw_reverse(raw_pk,pk,HW_KEM_PK);
    if(!hw_lock(d,err)) goto cleanup;
    if(!hw_profile(d,2,err) || !hw_ack(d,4,raw_pk,sizeof raw_pk,err) ||
       !hw_command(d,2,8,NULL,0,sizeof result,0,result,sizeof result,NULL,err)) goto finish;
    /* CT and K are independent whole fields, never reverse the combined reply. */
    hw_reverse(ct,result,HW_CT); hw_reverse(key,result+HW_CT,HW_KEY);
    *cn=HW_CT; ok=1;
finish:
    LeaveCriticalSection(&d->lock);
cleanup:
    lc_zero(raw_pk,sizeof raw_pk); lc_zero(result,sizeof result);
    return ok;
}

static int hw_decaps(lc_device *base,const uint8_t *ct,size_t cn,uint8_t *key,char *err)
{
    hw_device *d=(hw_device *)base;
    uint8_t raw_ct[HW_CT],result[HW_KEY];
    int ok=0;
    if(key) lc_zero(key,HW_KEY);
    if(!ct || cn!=HW_CT || !key) return lc_error(err,"LC01 invalid decapsulation field size");
    hw_reverse(raw_ct,ct,HW_CT);
    if(!hw_lock(d,err)) goto cleanup;
    if(!d->have_kem) { (void)lc_error(err,"LC01 KEM private key not generated"); goto finish; }
    if(!hw_profile(d,2,err) || !hw_ack(d,5,d->kem_sk,HW_KEM_SK,err) ||
       !hw_command(d,2,9,raw_ct,sizeof raw_ct,HW_KEY,0,result,sizeof result,NULL,err)) goto finish;
    hw_reverse(key,result,HW_KEY); ok=1;
finish:
    LeaveCriticalSection(&d->lock);
cleanup:
    lc_zero(raw_ct,sizeof raw_ct); lc_zero(result,sizeof result);
    return ok;
}

static void hw_close(lc_device *base)
{
    hw_device *d=(hw_device *)base;
    if(!d) return;
    /* The owner must stop issuing new calls before close, as for any device. */
    EnterCriticalSection(&d->lock);
    if(d->port!=INVALID_HANDLE_VALUE) (void)CloseHandle(d->port);
    lc_zero(d->sign_sk,sizeof d->sign_sk); lc_zero(d->kem_sk,sizeof d->kem_sk);
    LeaveCriticalSection(&d->lock);
    DeleteCriticalSection(&d->lock);
    lc_zero(d,sizeof *d);
    free(d);
}

static const lc_device_ops hw_ops={
    hw_close,hw_sign_keygen,hw_sign,hw_verify,hw_kem_keygen,hw_encaps,hw_decaps
};

static int hw_port_name(const char *port,char name[64],char *err)
{
    const char *digits;
    size_t i,n;
    int nonzero=0;
    if(!port) return lc_error(err,"LC01 COM port required");
    if(strncmp(port,"\\\\.\\",4)==0) port+=4;
    if(!((port[0]=='C' || port[0]=='c') &&
         (port[1]=='O' || port[1]=='o') && (port[2]=='M' || port[2]=='m')))
        return lc_error(err,"LC01 expected COM port name");
    digits=port+3; n=strlen(digits);
    if(!n || n>10u) return lc_error(err,"LC01 invalid COM port number");
    for(i=0;i<n;++i) {
        if(digits[i]<'0' || digits[i]>'9') return lc_error(err,"LC01 invalid COM port number");
        if(digits[i]!='0') nonzero=1;
    }
    if(!nonzero) return lc_error(err,"LC01 invalid COM port number");
    (void)snprintf(name,64,"\\\\.\\COM%s",digits);
    return 1;
}

lc_device *lc_hw_open(const lc_device_config *config,char *err)
{
    static const uint8_t clock[]={
        1,6,0x10,0,0,0,0,0,0x10,8,0,0,0,0,0,0xff,0,0,0,0,0
    };
    hw_device *d;
    DCB state;
    COMMTIMEOUTS timeouts;
    char name[64];
    uint8_t seed[16],response[HW_WIRE_MAX],ack[1];
    size_t rx_n=0;
    int ok=0;
    if(!config) { (void)lc_error(err,"LC01 device configuration required"); return NULL; }
    if(config->mode!=LC_HARDWARE) { (void)lc_error(err,"LC01 hardware mode required"); return NULL; }
    if(!hw_port_name(config->port,name,err)) return NULL;
    if(config->hooks.cancelled && config->hooks.cancelled(config->hooks.ctx)) {
        (void)lc_error(err,"LC01 operation cancelled"); return NULL;
    }
    d=(hw_device *)calloc(1,sizeof *d);
    if(!d) { (void)lc_error(err,"LC01 allocation failed"); return NULL; }
    d->base.ops=&hw_ops; d->base.mode=LC_HARDWARE;
    d->port=INVALID_HANDLE_VALUE; d->hooks=config->hooks;
    d->timeout_ms=config->timeout_ms?config->timeout_ms:20000u;
    d->interval_ms=config->interval_ms?config->interval_ms:80u;
    InitializeCriticalSection(&d->lock);
    d->port=CreateFileA(name,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED,NULL);
    if(d->port==INVALID_HANDLE_VALUE) { (void)hw_winerror(err,"open COM port"); goto finish; }
    memset(&state,0,sizeof state); state.DCBlength=sizeof state;
    if(!GetCommState(d->port,&state)) { (void)hw_winerror(err,"get COM configuration"); goto finish; }
    state.BaudRate=config->baud?config->baud:38580u;
    state.ByteSize=8; state.Parity=NOPARITY; state.StopBits=ONESTOPBIT;
    state.fBinary=TRUE; state.fParity=FALSE;
    state.fOutxCtsFlow=FALSE; state.fOutxDsrFlow=FALSE;
    state.fDtrControl=DTR_CONTROL_ENABLE; state.fDsrSensitivity=FALSE;
    state.fTXContinueOnXoff=TRUE; state.fOutX=FALSE; state.fInX=FALSE;
    state.fErrorChar=FALSE; state.fNull=FALSE;
    state.fRtsControl=RTS_CONTROL_ENABLE; state.fAbortOnError=FALSE;
    if(!SetCommState(d->port,&state)) { (void)hw_winerror(err,"set COM configuration"); goto finish; }
    memset(&timeouts,0,sizeof timeouts);
    timeouts.ReadTotalTimeoutConstant=d->timeout_ms<200u?d->timeout_ms:200u;
    timeouts.WriteTotalTimeoutConstant=d->timeout_ms;
    if(!SetCommTimeouts(d->port,&timeouts)) { (void)hw_winerror(err,"set COM timeouts"); goto finish; }
    if(!SetupComm(d->port,LC_FRAME_MAX,LC_FRAME_MAX)) { (void)hw_winerror(err,"set COM queues"); goto finish; }
    /* Discard stale bytes only at initial open, never to conceal a bad response. */
    if(!PurgeComm(d->port,PURGE_RXCLEAR|PURGE_TXCLEAR)) { (void)hw_winerror(err,"clear initial COM queues"); goto finish; }
    if(!lc_random(seed,sizeof seed)) { (void)lc_error(err,"LC01 initialization randomness failed"); goto finish; }
    if(!hw_exchange(d,clock,sizeof clock,1,response,sizeof response,&rx_n,err)) goto finish;
    if(!hw_command(d,1,3,seed,sizeof seed,HW_ANY,1,ack,sizeof ack,NULL,err)) goto finish;
    if(!hw_profile(d,1,err)) goto finish;
    ok=1;
finish:
    lc_zero(seed,sizeof seed); lc_zero(response,sizeof response);
    if(!ok) { hw_close(&d->base); return NULL; }
    return &d->base;
}

#else
lc_device *lc_hw_open(const lc_device_config *config,char *err)
{
    (void)config;
    (void)lc_error(err,"LC01 COM backend requires Windows");
    return NULL;
}
#endif
