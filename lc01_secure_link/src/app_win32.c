#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commdlg.h>
#include <shlobj.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <limits.h>
#include <errno.h>
#include "app.h"
#include "session.h"
#include "crypto.h"

/* One worker owns all device, session, file and socket operations. The window
 * thread may only shutdown the published socket during cancellation. UI events
 * own their copied text. Both command and event queues have fixed bounds. */
#define APP_CLASS L"LC01SecureLinkWindow"
#define APP_TITLE L"LC01 安全通信"
#define PATH_CHARS 2048
#define COMMAND_LIMIT 16
#define EVENT_LIMIT 64
#define ID_LIMIT 4096
#define ACK_LIMIT 16
#define WM_LC_EVENT (WM_APP + 1)
#define WM_LC_DONE (WM_APP + 2)
#define IO_RECORD_MS 20000u
#define IO_HANDSHAKE_MS 300000u
#define IO_CONFIRM_MS 180000u

enum { C_ROLE=101,C_IP,C_PORT,C_COM,C_REFRESH,C_BAUD,C_SOFTWARE,C_CONNECT,
       C_DIR,C_BROWSE,C_STATUS,C_FP,C_CONFIRM,C_REJECT,C_LOG,C_INPUT,C_SEND,
       C_FILE,C_REKEY,C_HINT,C_PROTOCOL,C_ROLE_LABEL,C_IP_LABEL,C_PORT_LABEL,
       C_COM_LABEL,C_BAUD_LABEL,C_DIR_LABEL,C_FP_LABEL };
enum { C_COPY_FP=140,C_CLEAR,C_DISCONNECT };
enum { CMD_TEXT=1,CMD_FILE,CMD_REKEY };
enum { EV_LOG=1,EV_STATUS,EV_FINGERPRINT,EV_READY,EV_PAUSE };
/* Application rekey barrier (authenticated records): A START{0}=freeze,
 * B REQUEST{}=frozen/drained, A START{1}=commit. In-flight files and ACKs
 * drain before commit. This also handles crossing manual requests. */
enum { REKEY_PREPARE=0,REKEY_COMMIT=1 };

typedef struct {
    int type;
    size_t n;
    uint8_t data[LC_BLOCK];
    wchar_t path[PATH_CHARS];
} command;
typedef struct { int type; wchar_t text[LC_BLOCK+512]; } ui_event;
typedef struct {
    int role,mode;
    uint16_t port;
    uint32_t baud;
    wchar_t ip[64],directory[PATH_CHARS];
    char com[32];
} configuration;
typedef struct app {
    HWND window,control[160];
    HFONT title,font,mono;
    WNDPROC log_proc;
    HINSTANCE instance;
    int dpi,closing,ready,awaiting,paused,smoke;
    HANDLE thread,stop,commands,decision,event_slots;
    CRITICAL_SECTION lock;
    SOCKET published_socket;
    LONG accepted;
    command queue[COMMAND_LIMIT];
    unsigned head,count;
    configuration config;
    wchar_t directory[PATH_CHARS];
} app;
typedef struct {
    HANDLE file;
    void *hash;
    uint8_t id[16];
    uint64_t size,offset;
    wchar_t part[PATH_CHARS],final[PATH_CHARS];
} file_state;
typedef struct {
    int used,kind,waiting;
    uint8_t id[16];
    ULONGLONG deadline;
} pending_ack;
typedef struct {
    app *ui;
    SOCKET socket;
    WSAEVENT network;
    ULONGLONG deadline;
    lc_io io;
    lc_session session;
    lc_device *device;
    file_state tx,rx;
    pending_ack pending[ACK_LIMIT];
    uint8_t received[ID_LIMIT][16],id_prefix[8];
    unsigned received_count;
    uint64_t next_id;
    int rekey,prepare_sent,peer_drained,request_sent;
    ULONGLONG rekey_deadline;
} worker;

static int stopped(void *ctx)
{
    app *a=(app *)ctx;
    return WaitForSingleObject(a->stop,0)==WAIT_OBJECT_0;
}
static int wide_to_utf8(const wchar_t *s,uint8_t *out,size_t cap,size_t *n)
{
    int need=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s,-1,NULL,0,NULL,NULL);
    if(need<=0||(size_t)need>cap)return 0;
    if(!WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s,-1,(char *)out,need,NULL,NULL))return 0;
    *n=(size_t)need-1;return 1;
}
static int utf8_to_wide(const uint8_t *s,size_t n,wchar_t *out,size_t cap)
{
    int need;
    if(n>(size_t)INT_MAX||memchr(s,0,n))return 0;
    if(!n){if(!cap)return 0;out[0]=0;return 1;}
    need=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,(const char *)s,(int)n,NULL,0);
    if(need<=0||(size_t)need>=cap)return 0;
    if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,(const char *)s,(int)n,out,need))return 0;
    out[need]=0;return 1;
}
static int path_join(wchar_t *out,size_t cap,const wchar_t *dir,const wchar_t *name)
{
    size_t dn=wcslen(dir),nn=wcslen(name);
    int slash=dn&&dir[dn-1]!=L'\\'&&dir[dn-1]!=L'/';
    if(!dn||dn+(size_t)slash+nn>=cap)return 0;
    memcpy(out,dir,dn*sizeof *out);
    if(slash)out[dn++]=L'\\';
    memcpy(out+dn,name,(nn+1)*sizeof *out);return 1;
}
static int safe_basename(const wchar_t *name)
{
    size_t i,n=wcslen(name),base=0;
    wchar_t stem[16];
    if(!n||n>200||name[n-1]==L'.'||name[n-1]==L' ')return 0;
    for(i=0;i<n;++i){
        if(name[i]<32||name[i]==127||wcschr(L"<>:\"/\\|?*",name[i]))return 0;
        /* Avoid bidirectional controls that can disguise the committed name. */
        if((name[i]>=0x202a&&name[i]<=0x202e)||(name[i]>=0x2066&&name[i]<=0x2069))return 0;
    }
    while(base<n&&name[base]!=L'.'&&base<15){stem[base]=name[base];++base;}
    stem[base]=0;
    if(!_wcsicmp(stem,L"CON")||!_wcsicmp(stem,L"PRN")||!_wcsicmp(stem,L"AUX")||
       !_wcsicmp(stem,L"NUL")||!_wcsicmp(stem,L"CONIN$")||!_wcsicmp(stem,L"CONOUT$"))return 0;
    if(base==4&&(!_wcsnicmp(stem,L"COM",3)||!_wcsnicmp(stem,L"LPT",3))&&
       ((stem[3]>=L'0'&&stem[3]<=L'9')||stem[3]==0x00b9||stem[3]==0x00b2||stem[3]==0x00b3))return 0;
    return 1;
}
static void post_event(app *a,int type,const wchar_t *text)
{
    HANDLE wait[2]={a->stop,a->event_slots};
    ui_event *e;
    if(WaitForMultipleObjects(2,wait,FALSE,INFINITE)!=WAIT_OBJECT_0+1)return;
    e=(ui_event *)calloc(1,sizeof *e);
    if(!e){ReleaseSemaphore(a->event_slots,1,NULL);return;}
    e->type=type;
    if(text){wcsncpy(e->text,text,sizeof e->text/sizeof e->text[0]-1);}
    if(!PostMessageW(a->window,WM_LC_EVENT,0,(LPARAM)e)){
        free(e);ReleaseSemaphore(a->event_slots,1,NULL);
    }
}
static void post_error(app *a,const char *err)
{
    wchar_t text[512];
    if(!utf8_to_wide((const uint8_t *)err,strlen(err),text,512))wcscpy(text,L"操作失败（错误文本无法解码）");
    post_event(a,EV_LOG,text);
}
static int enqueue(app *a,const command *c)
{
    int ok=0;
    EnterCriticalSection(&a->lock);
    if(a->count<COMMAND_LIMIT){a->queue[(a->head+a->count)%COMMAND_LIMIT]=*c;++a->count;SetEvent(a->commands);ok=1;}
    LeaveCriticalSection(&a->lock);return ok;
}
static int dequeue(app *a,command *c,int allow_file)
{
    int ok=0;
    EnterCriticalSection(&a->lock);
    if(a->count&&(allow_file||a->queue[a->head].type!=CMD_FILE)){
        *c=a->queue[a->head];lc_zero(&a->queue[a->head],sizeof *c);
        a->head=(a->head+1)%COMMAND_LIMIT;--a->count;ok=1;
    }
    /* Reset while holding the same lock as producers: no lost wakeup. */
    if(!a->count)ResetEvent(a->commands);
    LeaveCriticalSection(&a->lock);return ok;
}
static void clear_commands(app *a)
{
    unsigned i;
    EnterCriticalSection(&a->lock);
    for(i=0;i<COMMAND_LIMIT;++i)lc_zero(&a->queue[i],sizeof a->queue[i]);
    a->head=a->count=0;
    ResetEvent(a->commands);
    LeaveCriticalSection(&a->lock);
}
static void publish_socket(worker *w,SOCKET s)
{
    EnterCriticalSection(&w->ui->lock);
    w->ui->published_socket=s;
    if(s!=INVALID_SOCKET&&stopped(w->ui))shutdown(s,SD_BOTH);
    LeaveCriticalSection(&w->ui->lock);
}
static void cancel_worker(app *a)
{
    SetEvent(a->stop);
    EnterCriticalSection(&a->lock);
    if(a->published_socket!=INVALID_SOCKET)shutdown(a->published_socket,SD_BOTH);
    LeaveCriticalSection(&a->lock);
}
static DWORD remaining(ULONGLONG deadline)
{
    ULONGLONG now=GetTickCount64(),delta;
    if(now>=deadline)return 0;
    delta=deadline-now;return delta>MAXDWORD-1?MAXDWORD-1:(DWORD)delta;
}
static int network_wait(worker *w,long wanted,char *err)
{
    HANDLE waits[2]={w->ui->stop,w->network};
    for(;;){
        WSANETWORKEVENTS events;
        DWORD result=WaitForMultipleObjects(2,waits,FALSE,remaining(w->deadline));
        if(result==WAIT_OBJECT_0)return lc_error(err,"cancelled");
        if(result==WAIT_TIMEOUT)return lc_error(err,"network operation total timeout");
        if(result!=WAIT_OBJECT_0+1)return lc_error(err,"network event wait failed");
        if(WSAEnumNetworkEvents(w->socket,w->network,&events)==SOCKET_ERROR)return lc_error(err,"network event failed");
        if(events.lNetworkEvents&FD_CLOSE)return lc_error(err,"peer disconnected");
        if(events.lNetworkEvents&wanted){
            int index=wanted==FD_CONNECT?FD_CONNECT_BIT:wanted==FD_ACCEPT?FD_ACCEPT_BIT:wanted==FD_WRITE?FD_WRITE_BIT:FD_READ_BIT;
            if(events.iErrorCode[index])return lc_error(err,"socket event error");
            return 1;
        }
    }
}
static int socket_transfer(worker *w,uint8_t *buffer,size_t n,int writing,char *err)
{
    size_t done=0;
    while(done<n){
        int got,amount;
        if(stopped(w->ui))return lc_error(err,"cancelled");
        if(!remaining(w->deadline))return lc_error(err,"network operation total timeout");
        amount=n-done>(size_t)INT_MAX?INT_MAX:(int)(n-done);
        got=writing?send(w->socket,(const char *)buffer+done,amount,0):recv(w->socket,(char *)buffer+done,amount,0);
        if(got>0){done+=(size_t)got;continue;}
        if(!got)return lc_error(err,"peer EOF during exact transfer");
        if(WSAGetLastError()!=WSAEWOULDBLOCK)return lc_error(err,"socket transfer failed");
        if(!network_wait(w,writing?FD_WRITE:FD_READ,err))return 0;
    }
    return 1;
}
static int socket_read(void *ctx,uint8_t *p,size_t n,char *err)
{return socket_transfer((worker *)ctx,p,n,0,err);}
static int socket_write(void *ctx,const uint8_t *p,size_t n,char *err)
{return socket_transfer((worker *)ctx,(uint8_t *)(uintptr_t)p,n,1,err);}
static int send_record(worker *w,uint8_t type,const uint8_t *p,size_t n,char *err)
{
    w->deadline=GetTickCount64()+IO_RECORD_MS;
    return lc_record_send(&w->session,&w->io,type,p,n,err);
}
static void close_file(file_state *f)
{
    if(f->file!=INVALID_HANDLE_VALUE){CloseHandle(f->file);f->file=INVALID_HANDLE_VALUE;}
    if(f->hash){lc_hash_free(f->hash);f->hash=NULL;}
    if(f->part[0]){DeleteFileW(f->part);f->part[0]=0;}
}

static int open_network(worker *w,char *err)
{
    const configuration *c=&w->ui->config;
    struct sockaddr_in address;
    int one=1;
    memset(&address,0,sizeof address);address.sin_family=AF_INET;address.sin_port=htons(c->port);
    if(c->role){
        if(InetPtonW(AF_INET,c->ip,&address.sin_addr)!=1)return lc_error(err,"invalid peer IPv4 address");
    }else address.sin_addr.s_addr=htonl(INADDR_ANY);
    w->socket=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(w->socket==INVALID_SOCKET)return lc_error(err,"socket creation failed");
    publish_socket(w,w->socket);
    w->deadline=GetTickCount64()+IO_HANDSHAKE_MS;
    if(!c->role){
        SOCKET accepted_socket,listener;
        if(setsockopt(w->socket,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(const char *)&one,sizeof one)==SOCKET_ERROR||
           bind(w->socket,(const struct sockaddr *)&address,sizeof address)==SOCKET_ERROR||
           listen(w->socket,1)==SOCKET_ERROR||
           WSAEventSelect(w->socket,w->network,FD_ACCEPT|FD_CLOSE)==SOCKET_ERROR)
            return lc_error(err,"listen failed (port may already be in use)");
        post_event(w->ui,EV_STATUS,L"A 正在监听，等待 B 连接；可随时断开");
        /* Listening itself has no arbitrary timeout. */
        for(;;){
            HANDLE waits[2]={w->ui->stop,w->network};
            WSANETWORKEVENTS events;
            DWORD result=WaitForMultipleObjects(2,waits,FALSE,INFINITE);
            if(result==WAIT_OBJECT_0)return lc_error(err,"cancelled");
            if(result!=WAIT_OBJECT_0+1||WSAEnumNetworkEvents(w->socket,w->network,&events)==SOCKET_ERROR)
                return lc_error(err,"listener wait failed");
            if(!(events.lNetworkEvents&FD_ACCEPT))return lc_error(err,"listener closed");
            accepted_socket=accept(w->socket,NULL,NULL);
            if(accepted_socket!=INVALID_SOCKET)break;
            if(WSAGetLastError()!=WSAEWOULDBLOCK)return lc_error(err,"accept failed");
        }
        listener=w->socket;publish_socket(w,INVALID_SOCKET);closesocket(listener);
        w->socket=accepted_socket;publish_socket(w,w->socket);
        WSAResetEvent(w->network);
    }
    if(WSAEventSelect(w->socket,w->network,FD_READ|FD_WRITE|FD_CONNECT|FD_CLOSE)==SOCKET_ERROR)
        return lc_error(err,"socket event setup failed");
    if(c->role){
        post_event(w->ui,EV_STATUS,L"B 正在连接 A…");
        if(connect(w->socket,(const struct sockaddr *)&address,sizeof address)==SOCKET_ERROR){
            if(WSAGetLastError()!=WSAEWOULDBLOCK||!network_wait(w,FD_CONNECT,err))return lc_error(err,"connect failed / cancelled / timeout");
        }
    }
    return !stopped(w->ui);
}
static int establish_session(worker *w,char *err)
{
    lc_hooks hooks={stopped,NULL,w->ui};
    HANDLE waits[3]={w->ui->stop,w->ui->decision,w->network};
    wchar_t fp[65];
    int accept;
    /* No business call can run between handshake and both confirmations. */
    post_event(w->ui,EV_PAUSE,L"正在握手；业务发送已暂停");
    post_event(w->ui,EV_STATUS,L"正在双向签名、KEM 与密钥确认…");
    ResetEvent(w->ui->decision);InterlockedExchange(&w->ui->accepted,0);
    lc_session_close(&w->session);
    w->deadline=GetTickCount64()+IO_HANDSHAKE_MS;
    if(!lc_handshake(&w->session,w->device,&w->io,w->ui->config.role,hooks,err))return 0;
    if(strlen(w->session.fingerprint)!=64||
       !utf8_to_wide((const uint8_t *)w->session.fingerprint,64,fp,65))return lc_error(err,"invalid fingerprint");
    post_event(w->ui,EV_FINGERPRINT,fp);
    post_event(w->ui,EV_STATUS,L"请经可信独立渠道逐字核对完整指纹，再由双方分别确认（本端等待可取消）");
    for(;;){
        DWORD result=WaitForMultipleObjects(3,waits,FALSE,INFINITE);
        if(result==WAIT_OBJECT_0)return lc_error(err,"cancelled while checking fingerprint");
        if(result==WAIT_OBJECT_0+1)break;
        if(result==WAIT_OBJECT_0+2){
            WSANETWORKEVENTS events;
            if(WSAEnumNetworkEvents(w->socket,w->network,&events)==SOCKET_ERROR||
               (events.lNetworkEvents&FD_CLOSE))return lc_error(err,"peer disconnected while checking fingerprint");
            /* Peer acceptance may already be buffered. Only the core consumes it. */
        }else return lc_error(err,"fingerprint wait failed");
    }
    accept=InterlockedCompareExchange(&w->ui->accepted,0,0)>0;
    post_event(w->ui,EV_PAUSE,accept?L"本端已确认，等待对端确认（最多 180 秒）":L"本端拒绝指纹");
    w->deadline=GetTickCount64()+IO_CONFIRM_MS;
    if(!lc_session_confirm(&w->session,&w->io,accept,err))return 0;
    clear_commands(w->ui);
    if(!lc_random(w->id_prefix,sizeof w->id_prefix))return lc_error(err,"message ID random generation failed");
    w->next_id=0;w->received_count=0;
    w->rekey=w->prepare_sent=w->peer_drained=w->request_sent=0;
    w->rekey_deadline=0;
    post_event(w->ui,EV_READY,L"双方指纹确认通过；可以发送文本和文件");
    return 1;
}
static int ack_slot(worker *w)
{
    int i;for(i=0;i<ACK_LIMIT;++i)if(!w->pending[i].used)return i;
    return -1;
}
static int pending_any(const worker *w)
{
    int i;for(i=0;i<ACK_LIMIT;++i)if(w->pending[i].used)return 1;
    return 0;
}
static int new_id(worker *w,uint8_t id[16],char *err)
{
    if(w->next_id>=ID_LIMIT)return lc_error(err,"message limit reached; request rekey");
    memcpy(id,w->id_prefix,8);lc_put64(id+8,++w->next_id);return 1;
}
static void pending_add(worker *w,int slot,const uint8_t id[16],int kind,int waiting)
{
    pending_ack *p=&w->pending[slot];
    p->used=1;p->kind=kind;p->waiting=waiting;memcpy(p->id,id,16);
    p->deadline=waiting?GetTickCount64()+IO_RECORD_MS:0;
}
static int mark_received(worker *w,const uint8_t id[16],char *err)
{
    unsigned i;
    for(i=0;i<w->received_count;++i)if(lc_equal(w->received[i],id,16))return lc_error(err,"repeated application message ID");
    if(w->received_count>=ID_LIMIT)return lc_error(err,"receive ID limit; rekey required");
    memcpy(w->received[w->received_count++],id,16);return 1;
}
static int staging_path(const wchar_t *directory,wchar_t *out,size_t cap,char *err)
{
    DWORD attributes;
    if(!path_join(out,cap,directory,L".lc01-staging"))return lc_error(err,"receive staging path too long");
    if(!CreateDirectoryW(out,NULL)&&GetLastError()!=ERROR_ALREADY_EXISTS)
        return lc_error(err,"cannot create private receive staging directory");
    attributes=GetFileAttributesW(out);
    if(attributes==INVALID_FILE_ATTRIBUTES||!(attributes&FILE_ATTRIBUTE_DIRECTORY)||
       (attributes&FILE_ATTRIBUTE_REPARSE_POINT))return lc_error(err,"receive staging directory is unsafe");
    (void)SetFileAttributesW(out,attributes|FILE_ATTRIBUTE_HIDDEN);
    return 1;
}
static void cleanup_staging(const wchar_t *directory)
{
    wchar_t stage[PATH_CHARS],pattern[PATH_CHARS],path[PATH_CHARS];WIN32_FIND_DATAW found;HANDLE search;
    if(!staging_path(directory,stage,PATH_CHARS,NULL))return;
    if(!path_join(pattern,PATH_CHARS,stage,L"*"))return;
    search=FindFirstFileW(pattern,&found);
    if(search==INVALID_HANDLE_VALUE)return;
    do {
        if(!(found.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&path_join(path,PATH_CHARS,stage,found.cFileName))
            (void)DeleteFileW(path);
    } while(FindNextFileW(search,&found));
    FindClose(search);
}
static int send_ack(worker *w,const uint8_t id[16],uint8_t kind,char *err)
{
    uint8_t p[17];memcpy(p,id,16);p[16]=kind;
    return send_record(w,LC_ACK,p,sizeof p,err);
}
static int receive_ack(worker *w,const uint8_t *p,size_t n,char *err)
{
    int i;
    if(n!=17)return lc_error(err,"invalid ACK length");
    for(i=0;i<ACK_LIMIT;++i){
        pending_ack *a=&w->pending[i];
        if(a->used&&lc_equal(a->id,p,16)){
            if(!a->waiting||a->kind!=p[16])return lc_error(err,"unexpected ACK kind / premature file ACK");
            a->used=0;
            post_event(w->ui,EV_LOG,p[16]==LC_TEXT?L"[对端确认] 文本已接受":L"[对端确认] 文件已校验并保存");
            post_event(w->ui,EV_STATUS,p[16]==LC_TEXT?L"对端已确认文本送达":L"对端已校验并保存文件");
            return 1;
        }
    }
    return lc_error(err,"unknown / repeated ACK ID");
}
static int make_receive_file(worker *w,const wchar_t *name,char *err)
{
    wchar_t token[33],leaf[280],partial[280],stage[PATH_CHARS];
    uint8_t random[16];char hex[33];
    DWORD attributes=GetFileAttributesW(w->ui->config.directory);
    if(attributes==INVALID_FILE_ATTRIBUTES){
        if(!CreateDirectoryW(w->ui->config.directory,NULL))return lc_error(err,"cannot create receive directory");
        attributes=GetFileAttributesW(w->ui->config.directory);
    }
    if(!(attributes&FILE_ATTRIBUTE_DIRECTORY)||(attributes&FILE_ATTRIBUTE_REPARSE_POINT))return lc_error(err,"receive directory must be a real directory");
    if(!lc_random(random,sizeof random))return lc_error(err,"temporary filename random failed");
    lc_hex(random,sizeof random,hex);
    if(!utf8_to_wide((const uint8_t *)hex,32,token,33))return lc_error(err,"filename conversion failed");
    /* Random prefix also guarantees that existing user files are never replaced.
     * MoveFileEx without REPLACE_EXISTING independently enforces no overwrite. */
    if(!staging_path(w->ui->config.directory,stage,PATH_CHARS,err))return 0;
    if(swprintf(leaf,sizeof leaf/sizeof leaf[0],L"%ls_%ls",token,name)<0||
       !path_join(w->rx.final,PATH_CHARS,w->ui->config.directory,leaf))return lc_error(err,"receive path too long");
    if(swprintf(partial,sizeof partial/sizeof partial[0],L"%ls.part",leaf)<0||
       !path_join(w->rx.part,PATH_CHARS,stage,partial))return lc_error(err,"temporary path too long");
    w->rx.file=CreateFileW(w->rx.part,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_TEMPORARY,NULL);
    if(w->rx.file==INVALID_HANDLE_VALUE){w->rx.part[0]=0;return lc_error(err,"cannot exclusively create receive file");}
    w->rx.hash=lc_hash_new();
    if(!w->rx.hash)return lc_error(err,"receive SHA-256 initialization failed");
    return 1;
}
static int receive_file_begin(worker *w,const uint8_t *p,size_t n,char *err)
{
    wchar_t name[201];
    if(n<=24||n>224||w->rx.file!=INVALID_HANDLE_VALUE||w->rx.hash)
        return lc_error(err,"invalid / overlapping FILE_BEGIN");
    if(!utf8_to_wide(p+24,n-24,name,201)||!safe_basename(name))return lc_error(err,"unsafe / invalid UTF-8 filename");
    if(lc_get64(p+16)>LC_MAX_FILE)return lc_error(err,"file exceeds 16 MiB limit");
    if(!mark_received(w,p,err))return 0;
    memcpy(w->rx.id,p,16);w->rx.size=lc_get64(p+16);w->rx.offset=0;
    if(!make_receive_file(w,name,err))return 0;
    post_event(w->ui,EV_LOG,L"[接收文件] 开始写入临时文件；完成校验前不发布");
    post_event(w->ui,EV_STATUS,L"正在经认证通道接收文件；完成校验前不发布");
    return 1;
}
static int receive_file_chunk(worker *w,const uint8_t *p,size_t n,char *err)
{
    DWORD written=0;
    if(n<=24||n>LC_BLOCK||w->rx.file==INVALID_HANDLE_VALUE||!lc_equal(w->rx.id,p,16)||
       lc_get64(p+16)!=w->rx.offset||n-24>w->rx.size-w->rx.offset)
        return lc_error(err,"unknown / out-of-order / excessive FILE_CHUNK");
    if(!WriteFile(w->rx.file,p+24,(DWORD)(n-24),&written,NULL)||written!=n-24||
       !lc_hash_update(w->rx.hash,p+24,n-24))return lc_error(err,"receive file write / hash failed");
    w->rx.offset+=n-24;return 1;
}
static int receive_file_end(worker *w,const uint8_t *p,size_t n,char *err)
{
    uint8_t digest[32];void *hash;
    wchar_t message[PATH_CHARS+80];
    int hash_ok;
    if(n!=48||w->rx.file==INVALID_HANDLE_VALUE||!lc_equal(w->rx.id,p,16)||w->rx.offset!=w->rx.size)
        return lc_error(err,"unknown / premature FILE_END");
    hash=w->rx.hash;w->rx.hash=NULL;hash_ok=lc_hash_final(hash,digest);
    if(!hash_ok||!lc_equal(digest,p+16,32))return lc_error(err,"file SHA-256 mismatch");
    if(!FlushFileBuffers(w->rx.file))return lc_error(err,"cannot flush received file");
    if(!CloseHandle(w->rx.file)){w->rx.file=INVALID_HANDLE_VALUE;return lc_error(err,"cannot close received file");}
    w->rx.file=INVALID_HANDLE_VALUE;
    if(!MoveFileExW(w->rx.part,w->rx.final,MOVEFILE_WRITE_THROUGH))return lc_error(err,"cannot commit received file without overwrite");
    w->rx.part[0]=0;
    (void)SetFileAttributesW(w->rx.final,FILE_ATTRIBUTE_NORMAL);
    swprintf(message,sizeof message/sizeof message[0],L"[文件已保存] %ls",w->rx.final);
    post_event(w->ui,EV_LOG,message);
    post_event(w->ui,EV_STATUS,L"文件认证与 SHA-256 校验通过，已原子保存");
    return send_ack(w,p,LC_FILE_END,err);
}
static int start_send_file(worker *w,const wchar_t *path,int slot,char *err)
{
    const wchar_t *name=path,*q;
    LARGE_INTEGER size;
    uint8_t p[224];size_t nn;
    for(q=path;*q;++q)if(*q==L'\\'||*q==L'/')name=q+1;
    if(!safe_basename(name)||!wide_to_utf8(name,p+24,sizeof p-24,&nn)||nn>200)
        return lc_error(err,"filename must be a safe basename of at most 200 UTF-8 bytes");
    w->tx.file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,NULL);
    if(w->tx.file==INVALID_HANDLE_VALUE)return lc_error(err,"cannot open selected file");
    if(GetFileType(w->tx.file)!=FILE_TYPE_DISK||!GetFileSizeEx(w->tx.file,&size)||size.QuadPart<0||
       (uint64_t)size.QuadPart>LC_MAX_FILE){close_file(&w->tx);return lc_error(err,"selected file must be a disk file no larger than 16 MiB");}
    w->tx.hash=lc_hash_new();
    if(!w->tx.hash||!new_id(w,w->tx.id,err)){close_file(&w->tx);return lc_error(err,"send file hash / ID initialization failed");}
    w->tx.size=(uint64_t)size.QuadPart;w->tx.offset=0;
    memcpy(p,w->tx.id,16);lc_put64(p+16,w->tx.size);
    if(!send_record(w,LC_FILE_BEGIN,p,24+nn,err))return 0;
    pending_add(w,slot,w->tx.id,LC_FILE_END,0);
    post_event(w->ui,EV_LOG,L"[发送文件] 已发送开始记录，正在分块传输…");
    post_event(w->ui,EV_STATUS,L"文件正在经认证通道分块发送");
    return 1;
}
static int send_file_step(worker *w,char *err)
{
    uint8_t p[LC_BLOCK];DWORD got=0;
    size_t amount;
    if(w->tx.file==INVALID_HANDLE_VALUE)return 1;
    memcpy(p,w->tx.id,16);
    if(w->tx.offset<w->tx.size){
        amount=w->tx.size-w->tx.offset>LC_BLOCK-24?LC_BLOCK-24:(size_t)(w->tx.size-w->tx.offset);
        if(!ReadFile(w->tx.file,p+24,(DWORD)amount,&got,NULL)||got!=amount||
           !lc_hash_update(w->tx.hash,p+24,amount))return lc_error(err,"send file read / hash failed");
        lc_put64(p+16,w->tx.offset);
        if(!send_record(w,LC_FILE_CHUNK,p,amount+24,err))return 0;
        w->tx.offset+=amount;return 1; /* At most one chunk per event-loop turn. */
    }else{
        int i;void *hash=w->tx.hash;
        w->tx.hash=NULL;
        if(!lc_hash_final(hash,p+16))return lc_error(err,"send file hash final failed");
        if(!send_record(w,LC_FILE_END,p,48,err))return 0;
        CloseHandle(w->tx.file);w->tx.file=INVALID_HANDLE_VALUE;
        for(i=0;i<ACK_LIMIT;++i)if(w->pending[i].used&&lc_equal(w->pending[i].id,w->tx.id,16)){
            w->pending[i].waiting=1;w->pending[i].deadline=GetTickCount64()+IO_RECORD_MS;break;
        }
        post_event(w->ui,EV_LOG,L"[发送文件] 数据发送完毕，等待对端校验与保存确认");return 1;
    }
}

static int socket_has_input(worker *w)
{
    fd_set read_set;
    struct timeval timeout={0,0};
    int result;
    FD_ZERO(&read_set);FD_SET(w->socket,&read_set);
    result=select(0,&read_set,NULL,NULL,&timeout);
    return result>0 && FD_ISSET(w->socket,&read_set);
}
static void sanitize_remote_text(const wchar_t *,wchar_t *,size_t);
static int send_text(worker *w,const command *c,char *err)
{
    uint8_t bytes[LC_BLOCK];size_t n;
    wchar_t shown[LC_BLOCK+64],line[LC_BLOCK+96];
    int slot=ack_slot(w);
    if(slot<0)return lc_error(err,"too many messages awaiting peer acknowledgement");
    if(c->n>LC_BLOCK-17)return lc_error(err,"text exceeds 4079 UTF-8 bytes");
    if(!wide_to_utf8((const wchar_t *)c->data,bytes+16,LC_BLOCK-16,&n)||!n)
        return lc_error(err,"text is empty or contains an invalid Unicode character");
    if(!new_id(w,bytes,err))return 0;
    if(!send_record(w,LC_TEXT,bytes,16+n,err))return 0;
    pending_add(w,slot,bytes,LC_TEXT,1);
    sanitize_remote_text((const wchar_t *)c->data,shown,LC_BLOCK+64);
    swprintf(line,sizeof line/sizeof line[0],L"[本机] %ls",shown);
    post_event(w->ui,EV_LOG,line);
    post_event(w->ui,EV_LOG,L"[本机发送] 文本已完整发出并认证，等待对端确认");
    post_event(w->ui,EV_STATUS,L"文本已加密发送；等待对端认证并确认");
    return 1;
}
static void sanitize_remote_text(const wchar_t *input,wchar_t *output,size_t cap)
{
    size_t used=0;
    while(*input&&used+1<cap){
        wchar_t ch=*input++;
        if(ch==L'\r'||ch==L'\n'||ch==L'\t') {
            if(used+2>=cap)break;
            output[used++]=L'\\';output[used++]=ch==L'\r'?L'r':ch==L'\n'?L'n':L't';
        }else if(ch<32||ch==127||ch==0x061c||(ch>=0x200e&&ch<=0x200f)||
                 (ch>=0x202a&&ch<=0x202e)||(ch>=0x2066&&ch<=0x2069)||ch==0x2028||ch==0x2029){
            output[used++]=L'?';
        }else output[used++]=ch;
    }
    output[used]=0;
}
static int process_record(worker *w,uint8_t type,uint8_t *p,size_t n,char *err)
{
    wchar_t text[LC_BLOCK+64],shown[LC_BLOCK+64];
    switch(type){
    case LC_TEXT:
        if(n<17||n>LC_BLOCK)return lc_error(err,"invalid ciphertext text record");
        if(!mark_received(w,p,err)||!utf8_to_wide(p+16,n-16,text,LC_BLOCK+64))
            return lc_error(err,"invalid UTF-8 text");
        if(!send_ack(w,p,LC_TEXT,err))return 0;
        {
            wchar_t line[LC_BLOCK+96];
            sanitize_remote_text(text,shown,LC_BLOCK+64);
            swprintf(line,sizeof line/sizeof line[0],L"[对端] %ls",shown);
            post_event(w->ui,EV_LOG,line);
            post_event(w->ui,EV_STATUS,L"已认证并接收对端文本；ACK 已发送");
        }
        return 1;
    case LC_ACK:return receive_ack(w,p,n,err);
    case LC_FILE_BEGIN:return receive_file_begin(w,p,n,err);
    case LC_FILE_CHUNK:return receive_file_chunk(w,p,n,err);
    case LC_FILE_END:return receive_file_end(w,p,n,err);
    case LC_CLOSE:return lc_error(err,"peer closed the session");
    default:return lc_error(err,"unexpected record type in this state");
    }
}
static int rekey_barrier(worker *w,int received_type,uint8_t *p,size_t n,char *err)
{
    uint8_t one=0,type;size_t got=0;
    int sent_start=0;
    (void)n;
    if(w->tx.file!=INVALID_HANDLE_VALUE||w->rx.file!=INVALID_HANDLE_VALUE||pending_any(w))
        return lc_error(err,"rekey rejected while a file or acknowledgement is active");
    if(received_type==LC_REKEY_START){
        if(!send_record(w,LC_REKEY_START,&one,1,err))return 0;
        return 1;
    }
    if(received_type==LC_REKEY_REQUEST){
        if(!send_record(w,LC_REKEY_START,&one,1,err))return 0;
        sent_start=1;
    }else if(received_type==0){
        if(!send_record(w,LC_REKEY_REQUEST,NULL,0,err))return 0;
    }else return lc_error(err,"invalid rekey entry state");
    for(;;){
        w->deadline=GetTickCount64()+IO_RECORD_MS;
        if(!lc_record_receive(&w->session,&w->io,&type,p,LC_BLOCK,&got,err))return 0;
        if(type==LC_REKEY_REQUEST){
            if(sent_start)return lc_error(err,"duplicate rekey prepare request");
            if(!send_record(w,LC_REKEY_START,&one,1,err))return 0;
            sent_start=1;
        }else if(type==LC_REKEY_START){
            if(got!=1)return lc_error(err,"invalid rekey start payload");
            if(!sent_start&&!send_record(w,LC_REKEY_START,&one,1,err))return 0;
            return 1;
        }else if(type==LC_ACK){
            if(!receive_ack(w,p,got,err))return 0;
        }else return lc_error(err,"business record arrived during rekey barrier");
    }
}
static int check_ack_deadlines(worker *w,char *err)
{
    int i;ULONGLONG now=GetTickCount64();
    for(i=0;i<ACK_LIMIT;++i)
        if(w->pending[i].used&&w->pending[i].waiting&&now>=w->pending[i].deadline)
            return lc_error(err,"peer delivery acknowledgement timeout");
    return 1;
}
/* Returns 1 to continue, 2 to rekey on the same socket, 0 on fatal failure. */
static int business_loop(worker *w,char *err)
{
    uint8_t record[LC_BLOCK],type;size_t n=0;command c;HANDLE wait;
    for(;;){
        if(stopped(w->ui))return lc_error(err,"cancelled");
        if(w->tx.file!=INVALID_HANDLE_VALUE&&!send_file_step(w,err))return 0;
        if(!check_ack_deadlines(w,err))return 0;
        if(w->rekey&&w->tx.file==INVALID_HANDLE_VALUE&&w->rx.file==INVALID_HANDLE_VALUE&&!pending_any(w)){
            w->rekey=0;
            if(!rekey_barrier(w,0,record,0,err))return 0;
            clear_commands(w->ui);
            return 2;
        }
        if(socket_has_input(w)){
            w->deadline=GetTickCount64()+IO_RECORD_MS;
            if(!lc_record_receive(&w->session,&w->io,&type,record,LC_BLOCK,&n,err))return 0;
            if(type==LC_REKEY_REQUEST||type==LC_REKEY_START){
                w->rekey=1;
                if(w->tx.file!=INVALID_HANDLE_VALUE||w->rx.file!=INVALID_HANDLE_VALUE||pending_any(w))
                    return lc_error(err,"peer requested rekey during active transfer");
                if(!rekey_barrier(w,(int)type,record,n,err))return 0;
                clear_commands(w->ui);
                return 2;
            }
            if(!process_record(w,type,record,n,err))return 0;
            continue;
        }
        wait=w->ui->commands;
        WaitForSingleObject(wait,20);
        while(dequeue(w->ui,&c,1)){
            if(c.type==CMD_TEXT) {
                if(!send_text(w,&c,err)) {
                    if(!w->session.ready)return 0;
                    post_error(w->ui,err);continue;
                }
            }else if(c.type==CMD_FILE) {
                int slot=ack_slot(w),i,file_pending=0;
                if(w->tx.file!=INVALID_HANDLE_VALUE){
                    post_event(w->ui,EV_LOG,L"[发送文件] 当前文件尚未发完，新选择未进入发送队列");
                    continue;
                }
                for(i=0;i<ACK_LIMIT;++i)if(w->pending[i].used&&w->pending[i].kind==LC_FILE_END)file_pending=1;
                if(file_pending){
                    post_event(w->ui,EV_LOG,L"[发送文件] 上一个文件仍在等待对端确认，请稍后重试");
                    continue;
                }
                if(slot<0)return lc_error(err,"too many pending application records");
                if(!start_send_file(w,c.path,slot,err)) {
                    if(!w->session.ready)return 0;
                    post_error(w->ui,err);
                }
            }else if(c.type==CMD_REKEY) {
                if(w->tx.file!=INVALID_HANDLE_VALUE||w->rx.file!=INVALID_HANDLE_VALUE||pending_any(w)) {
                    w->rekey=1;
                    post_event(w->ui,EV_LOG,L"[换钥] 已登记；当前文件或确认完成后自动重新建钥");
                    continue;
                }
                if(!rekey_barrier(w,0,record,0,err))return 0;
                clear_commands(w->ui);
                return 2;
            }else return lc_error(err,"unknown UI command");
        }
    }
}
static void worker_cleanup(worker *w)
{
    if(w->tx.file!=INVALID_HANDLE_VALUE||w->rx.file!=INVALID_HANDLE_VALUE||w->rx.part[0]) {
        close_file(&w->tx);close_file(&w->rx);
    }
    clear_commands(w->ui);
    lc_session_close(&w->session);
    lc_device_close(w->device);w->device=NULL;
    if(w->socket!=INVALID_SOCKET) {
        publish_socket(w,INVALID_SOCKET);closesocket(w->socket);w->socket=INVALID_SOCKET;
    }
    if(w->network){WSACloseEvent(w->network);w->network=NULL;}
    lc_zero(&w->session,sizeof w->session);lc_zero(w->received,sizeof w->received);
}
static DWORD WINAPI worker_main(void *context)
{
    worker w;lc_device_config device;char err[LC_ERR_MAX]={0};WSADATA winsock;int ok=0;
    memset(&w,0,sizeof w);w.ui=(app *)context;w.socket=INVALID_SOCKET;
    w.tx.file=w.rx.file=INVALID_HANDLE_VALUE;
    if(WSAStartup(MAKEWORD(2,2),&winsock)!=0){post_error(w.ui,"Winsock initialization failed");goto done;}
    w.network=WSACreateEvent();
    if(w.network==WSA_INVALID_EVENT){post_error(w.ui,"network event creation failed");goto done;}
    if(!open_network(&w,err)){post_error(w.ui,err);goto done;}
    memset(&device,0,sizeof device);device.mode=w.ui->config.mode;device.port=w.ui->config.com;
    device.baud=w.ui->config.baud;device.timeout_ms=20000;device.interval_ms=80;
    device.hooks.cancelled=stopped;device.hooks.ctx=w.ui;
    w.device=lc_device_open(&device,err);
    if(!w.device){post_error(w.ui,err);goto done;}
    cleanup_staging(w.ui->config.directory);
    if(device.mode==LC_SOFTWARE)
        post_event(w.ui,EV_LOG,L"运行后端：软件验证（OpenSSL 真实 ML-DSA-44/ML-KEM-512；未访问 LC01）");
    else
        post_event(w.ui,EV_LOG,L"运行后端：LC01 硬件串口（固件声明 Dilithium2/Kyber512；互通待现场验证）");
    w.io.ctx=&w;w.io.read=socket_read;w.io.write=socket_write;
    for(;;){
        int state;
        if(!establish_session(&w,err)){post_error(w.ui,err);goto done;}
        state=business_loop(&w,err);
        if(state==2){
            post_event(w.ui,EV_PAUSE,L"正在同一连接上销毁旧会话并重新握手…");
            post_event(w.ui,EV_READY,L"旧会话已关闭；请重新核对新指纹");
            lc_session_close(&w.session);
            post_event(w.ui,EV_PAUSE,L"重新握手：等待双方再次核对指纹");
            continue;
        }
        if(state==1)break;
        post_error(w.ui,err);goto done;
    }
    ok=1;
done:
    worker_cleanup(&w);
    WSACleanup();
    post_event(w.ui,EV_READY,L"连接已安全关闭。可重新连接建立全新会话。");
    if(ok)post_event(w.ui,EV_STATUS,L"已断开；旧会话密钥已销毁");
    else {
        wchar_t detail[LC_ERR_MAX];
        if(err[0]&&utf8_to_wide((const uint8_t *)err,strlen(err),detail,LC_ERR_MAX))
            post_event(w.ui,EV_STATUS,detail);
        else post_event(w.ui,EV_STATUS,L"连接失败或已中止；旧会话密钥已销毁");
    }
    if(w.ui->window)PostMessageW(w.ui->window,WM_LC_DONE,ok?1:0,0);
    return 0;
}

static HWND child(app *a,const wchar_t *klass,const wchar_t *text,DWORD style,DWORD ex,int id)
{
    HWND h=CreateWindowExW(ex,klass,text,WS_CHILD|WS_VISIBLE|style,0,0,10,10,a->window,(HMENU)(INT_PTR)id,a->instance,NULL);
    if(h) {
        SendMessageW(h,WM_SETFONT,(WPARAM)a->font,TRUE);
        a->control[id]=h;
    }
    return h;
}
static void label(app *a,const wchar_t *text,int id,int x,int y,int w,int h)
{
    child(a,L"STATIC",text,SS_LEFT,0,id);
    SetWindowPos(a->control[id],NULL,x,y,w,h,SWP_NOZORDER);
}
static void move_control(app *a,int id,int x,int y,int w,int h)
{
    if(a->control[id])SetWindowPos(a->control[id],NULL,x,y,w,h,SWP_NOZORDER);
}
static void set_font(app *a,HWND h,HFONT font)
{
    (void)a;
    if(h)SendMessageW(h,WM_SETFONT,(WPARAM)font,TRUE);
}
static void layout(app *a,int width,int height)
{
    int left=20,panel=292,right=left+panel+18,content_width=width-right-20;
    int input_y=height-82,log_x=right,log_w=content_width;
    HWND header=a->control[C_STATUS];
    (void)header;
    if(content_width<420)content_width=420;
    if(input_y-172<140)input_y=322;
    move_control(a,C_ROLE_LABEL,left+14,96,90,22);move_control(a,C_ROLE,left+14,119,panel-28,220);
    move_control(a,C_IP_LABEL,left+14,151,180,22);move_control(a,C_IP,left+14,174,panel-28,30);
    move_control(a,C_PORT_LABEL,left+14,214,120,22);move_control(a,C_PORT,left+14,237,panel-28,30);
    move_control(a,C_SOFTWARE,left+14,276,panel-28,25);
    move_control(a,C_COM_LABEL,left+14,310,120,22);move_control(a,C_COM,left+14,333,panel-92,220);
    move_control(a,C_REFRESH,left+panel-72,333,58,30);
    move_control(a,C_BAUD_LABEL,left+14,372,120,22);move_control(a,C_BAUD,left+14,395,panel-28,30);
    move_control(a,C_CONNECT,left+14,441,panel-28,42);
    move_control(a,C_FP_LABEL,left+14,500,panel-28,22);move_control(a,C_FP,left+14,523,panel-28,78);
    move_control(a,C_CONFIRM,left+14,608,82,32);move_control(a,C_REJECT,left+102,608,82,32);
    move_control(a,C_COPY_FP,left+190,608,84,32);
    if(height>720){
        int d=height-720;
        move_control(a,C_FP,left+14,523,panel-28,78+(d>80?80:d));
        move_control(a,C_CONFIRM,left+14,631+(d>80?80:d),82,32);
        move_control(a,C_REJECT,left+102,631+(d>80?80:d),82,32);
        move_control(a,C_COPY_FP,left+190,631+(d>80?80:d),84,32);
    }
    move_control(a,C_STATUS,right,86,log_w,30);
    move_control(a,C_DISCONNECT,right+log_w-132,122,132,32);
    move_control(a,C_CLEAR,right+log_w-268,122,126,32);
    move_control(a,C_LOG,log_x,160,log_w,input_y-172);
    move_control(a,C_INPUT,right,input_y,log_w-116,42);move_control(a,C_SEND,right+log_w-106,input_y,106,42);
    move_control(a,C_FILE,right,input_y+50,130,32);move_control(a,C_REKEY,right+138,input_y+50,130,32);
    move_control(a,C_DIR_LABEL,right+276,input_y+50,64,32);move_control(a,C_DIR,right+344,input_y+50,log_w-412,32);
    move_control(a,C_BROWSE,right+log_w-60,input_y+50,60,32);
    if(height>=720){move_control(a,C_HINT,left+14,height-47,panel-28,32);ShowWindow(a->control[C_HINT],SW_SHOW);}
    else ShowWindow(a->control[C_HINT],SW_HIDE);
    ShowWindow(a->control[C_BROWSE],SW_SHOW);
}
static int wide_text(HWND h,wchar_t *out,size_t cap)
{
    int n;
    if(!h||!out||!cap)return 0;
    n=GetWindowTextW(h,out,(int)cap);
    if(n<0||(size_t)n>=cap)return 0;
    out[n]=0;return 1;
}
static void append_log(app *a,const wchar_t *text)
{
    HWND edit=a->control[C_LOG];
    SYSTEMTIME now;wchar_t line[LC_BLOCK+640];wchar_t *current,*combined;
    int length,offset=0,total;
    if(!edit||!text)return;
    GetLocalTime(&now);
    _snwprintf(line,sizeof line/sizeof line[0]-1,L"[%02u:%02u:%02u] %ls\r\n",(unsigned)now.wHour,(unsigned)now.wMinute,(unsigned)now.wSecond,text);
    line[sizeof line/sizeof line[0]-1]=0;
    length=GetWindowTextLengthW(edit);
    current=(wchar_t *)calloc((size_t)length+1,sizeof *current);
    total=(int)wcslen(line);
    if(!current)return;
    if(length)GetWindowTextW(edit,current,length+1);
    if(length>240000){offset=60000;length-=offset;}
    combined=(wchar_t *)calloc((size_t)length+(size_t)total+1,sizeof *combined);
    if(!combined){free(current);return;}
    if(length)memcpy(combined,current+offset,(size_t)length*sizeof *combined);
    memcpy(combined+length,line,((size_t)total+1)*sizeof *combined);
    SetWindowTextW(edit,combined);
    free(combined);free(current);
    SendMessageW(edit,EM_SETSEL,-1,-1);
    SendMessageW(edit,EM_SCROLLCARET,0,0);
}
static LRESULT CALLBACK protected_log_proc(HWND hwnd,UINT message,WPARAM wp,LPARAM lp)
{
    app *a=(app *)GetWindowLongPtrW(GetParent(hwnd),GWLP_USERDATA);
    if(message==WM_PASTE||message==WM_CUT||message==WM_CLEAR||message==WM_UNDO)return 0;
    if(message==WM_CHAR&&wp!=3)return 0;
    return CallWindowProcW(a?a->log_proc:DefWindowProcW,hwnd,message,wp,lp);
}
static void set_status(app *a,const wchar_t *text)
{
    SetWindowTextW(a->control[C_STATUS],text?text:L"");
    if(text)append_log(a,text);
}
static void update_controls(app *a,int running,int ready,int awaiting)
{
    int config_enabled=!running;
    int software=(int)SendMessageW(a->control[C_SOFTWARE],BM_GETCHECK,0,0)==BST_CHECKED;
    EnableWindow(a->control[C_ROLE],config_enabled);EnableWindow(a->control[C_IP],config_enabled);
    EnableWindow(a->control[C_PORT],config_enabled);EnableWindow(a->control[C_SOFTWARE],config_enabled);
    EnableWindow(a->control[C_COM],config_enabled&&!software);EnableWindow(a->control[C_REFRESH],config_enabled&&!software);
    EnableWindow(a->control[C_BAUD],config_enabled&&!software);
    EnableWindow(a->control[C_CONNECT],!running);
    EnableWindow(a->control[C_DISCONNECT],running);
    EnableWindow(a->control[C_CONFIRM],awaiting);EnableWindow(a->control[C_REJECT],awaiting);
    EnableWindow(a->control[C_SEND],ready);EnableWindow(a->control[C_FILE],ready);
    EnableWindow(a->control[C_REKEY],ready);
    EnableWindow(a->control[C_DIR],config_enabled);EnableWindow(a->control[C_BROWSE],config_enabled);
}
static void refresh_ports(app *a)
{
    HKEY key;DWORD index=0,type,size;wchar_t name[128],value[64];HWND combo=a->control[C_COM];
    SendMessageW(combo,CB_RESETCONTENT,0,0);
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"HARDWARE\\DEVICEMAP\\SERIALCOMM",0,KEY_READ,&key)==ERROR_SUCCESS){
        for(;;){
            size=sizeof value;type=0;
            if(RegEnumValueW(key,index++,name,&size,NULL,&type,(BYTE *)value,&size)!=ERROR_SUCCESS)break;
            if(type==REG_SZ||type==REG_EXPAND_SZ)SendMessageW(combo,CB_ADDSTRING,0,(LPARAM)value);
        }
        RegCloseKey(key);
    }
    if(SendMessageW(combo,CB_GETCOUNT,0,0))SendMessageW(combo,CB_SETCURSEL,0,0);
}
static int ensure_directory(const wchar_t *path,char *err)
{
    wchar_t parent[PATH_CHARS];wchar_t *slash;DWORD attr;
    if(!path||!*path)return lc_error(err,"receive directory is empty");
    wcscpy(parent,path);slash=wcsrchr(parent,L'\\');
    if(slash&&slash!=parent){*slash=0;if(GetFileAttributesW(parent)==INVALID_FILE_ATTRIBUTES)CreateDirectoryW(parent,NULL);}
    attr=GetFileAttributesW(path);
    if(attr==INVALID_FILE_ATTRIBUTES&&CreateDirectoryW(path,NULL))attr=GetFileAttributesW(path);
    if(attr==INVALID_FILE_ATTRIBUTES||!(attr&FILE_ATTRIBUTE_DIRECTORY))return lc_error(err,"cannot create receive directory");
    return 1;
}
static int read_configuration(app *a,char *err)
{
    wchar_t port[16],baud[16],com[32],ip[64],directory[PATH_CHARS];
    wchar_t *end;unsigned long port_value,baud_value;
    int role=(int)SendMessageW(a->control[C_ROLE],CB_GETCURSEL,0,0);
    if(role<0||role>1)return lc_error(err,"select endpoint A or B");
    if(!wide_text(a->control[C_PORT],port,16)||!wide_text(a->control[C_BAUD],baud,16)||
       !wide_text(a->control[C_IP],ip,64)||!wide_text(a->control[C_DIR],directory,PATH_CHARS))
        return lc_error(err,"configuration text is invalid");
    errno=0;port_value=wcstoul(port,&end,10);
    if(errno==ERANGE||*end||port_value<1||port_value>65535)return lc_error(err,"TCP port must be 1..65535");
    errno=0;baud_value=wcstoul(baud,&end,10);
    if(errno==ERANGE||*end||baud_value<1200||baud_value>4000000)return lc_error(err,"baud rate is outside the supported range");
    a->config.role=role;a->config.port=(uint16_t)port_value;a->config.baud=(uint32_t)baud_value;
    wcscpy(a->config.ip,ip);wcscpy(a->config.directory,directory);
    a->config.mode=SendMessageW(a->control[C_SOFTWARE],BM_GETCHECK,0,0)==BST_CHECKED?LC_SOFTWARE:LC_HARDWARE;
    a->config.com[0]=0;
    if(a->config.mode==LC_HARDWARE) {
        int index=(int)SendMessageW(a->control[C_COM],CB_GETCURSEL,0,0);
        if(index<0||!SendMessageW(a->control[C_COM],CB_GETLBTEXT,index,(LPARAM)com))return lc_error(err,"select the local LC01 COM port");
        if(WideCharToMultiByte(CP_ACP,0,com,-1,a->config.com,(int)sizeof a->config.com,NULL,NULL)<=0)
            return lc_error(err,"COM port name conversion failed");
    }
    return ensure_directory(a->config.directory,err);
}
static void start_worker(app *a)
{
    char err[LC_ERR_MAX]={0};
    if(a->thread){cancel_worker(a);set_status(a,L"正在停止当前会话…");return;}
    if(!read_configuration(a,err)){MessageBoxA(a->window,err,"配置错误",MB_ICONWARNING);return;}
    ResetEvent(a->stop);ResetEvent(a->commands);ResetEvent(a->decision);
    clear_commands(a);
    a->ready=0;a->awaiting=0;a->accepted=0;a->published_socket=INVALID_SOCKET;
    a->thread=CreateThread(NULL,0,worker_main,a,0,NULL);
    if(!a->thread){MessageBoxW(a->window,L"无法创建工作线程",L"启动失败",MB_ICONERROR);return;}
    update_controls(a,1,0,0);set_status(a,L"工作线程已启动；正在连接对端并执行签名握手…");
}
static void choose_file(app *a)
{
    OPENFILENAMEW dialog;wchar_t path[PATH_CHARS]={0};command c;
    static const wchar_t filter[]=L"图片和文件\0*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.webp;*.pdf;*.txt;*.bin\0所有文件\0*.*\0\0";
    memset(&dialog,0,sizeof dialog);dialog.lStructSize=sizeof dialog;dialog.hwndOwner=a->window;
    dialog.lpstrFilter=filter;dialog.lpstrFile=path;dialog.nMaxFile=PATH_CHARS;
    dialog.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR;
    dialog.lpstrTitle=L"选择要通过认证加密发送的文件";
    if(!GetOpenFileNameW(&dialog))return;
    memset(&c,0,sizeof c);c.type=CMD_FILE;wcscpy(c.path,path);
    if(!enqueue(a,&c))set_status(a,L"等待发送的命令过多，请稍后重试");
}
static void choose_directory(app *a)
{
    BROWSEINFOW browse;wchar_t path[PATH_CHARS];ITEMIDLIST *item;BOOL ok=FALSE;
    memset(&browse,0,sizeof browse);browse.hwndOwner=a->window;browse.lpszTitle=L"选择接收文件保存目录";browse.ulFlags=BIF_RETURNONLYFSDIRS|BIF_NEWDIALOGSTYLE;
    item=SHBrowseForFolderW(&browse);
    if(item){ok=SHGetPathFromIDListW(item,path);CoTaskMemFree(item);}
    if(ok)SetWindowTextW(a->control[C_DIR],path);
}
static void add_text_command(app *a)
{
    command c;wchar_t text[LC_BLOCK];
    if(!wide_text(a->control[C_INPUT],text,LC_BLOCK/sizeof text[0])||!text[0])return;
    memset(&c,0,sizeof c);c.type=CMD_TEXT;wcscpy((wchar_t *)c.data,text);
    if(enqueue(a,&c))SetWindowTextW(a->control[C_INPUT],L"");
    else set_status(a,L"待发送命令过多；文本尚未进入发送队列");
}
static void copy_fingerprint(app *a)
{
    wchar_t fp[128];HGLOBAL memory;void *dest;size_t bytes;
    if(!wide_text(a->control[C_FP],fp,128)||!fp[0])return;
    bytes=(wcslen(fp)+1)*sizeof(wchar_t);memory=GlobalAlloc(GMEM_MOVEABLE,bytes);
    if(!memory)return;
    dest=GlobalLock(memory);memcpy(dest,fp,bytes);GlobalUnlock(memory);
    if(!OpenClipboard(a->window)||!EmptyClipboard()||!SetClipboardData(CF_UNICODETEXT,memory)){
        GlobalFree(memory);CloseClipboard();return;
    }
    CloseClipboard();set_status(a,L"完整会话指纹已复制");
}
static void finish_close_if_ready(app *a,HWND hwnd)
{
    if(a->thread&&WaitForSingleObject(a->thread,0)==WAIT_TIMEOUT)return;
    if(a->thread){CloseHandle(a->thread);a->thread=NULL;}
    KillTimer(hwnd,1);
    DestroyWindow(hwnd);
}
static LRESULT CALLBACK window_proc(HWND hwnd,UINT message,WPARAM wp,LPARAM lp)
{
    app *a=(app *)GetWindowLongPtrW(hwnd,GWLP_USERDATA);
    if(message==WM_NCCREATE){CREATESTRUCTW *cs=(CREATESTRUCTW *)lp;a=(app *)cs->lpCreateParams;SetWindowLongPtrW(hwnd,GWLP_USERDATA,(LONG_PTR)a);}
    if(!a)return DefWindowProcW(hwnd,message,wp,lp);
    switch(message){
    case WM_COMMAND:
        switch(LOWORD(wp)){
        case C_CONNECT:start_worker(a);break;
        case C_REFRESH:refresh_ports(a);break;
        case C_SOFTWARE:update_controls(a,a->thread?1:0,a->ready,a->awaiting);InvalidateRect(hwnd,NULL,TRUE);break;
        case C_CONFIRM:if(a->awaiting){a->awaiting=0;a->accepted=1;SetEvent(a->decision);EnableWindow(a->control[C_CONFIRM],0);EnableWindow(a->control[C_REJECT],0);set_status(a,L"本端已确认；等待对端确认同一指纹");}break;
        case C_REJECT:if(a->awaiting){a->awaiting=0;a->accepted=0;SetEvent(a->decision);set_status(a,L"本端拒绝指纹；会话将断开");}break;
        case C_SEND:add_text_command(a);break;
        case C_FILE:choose_file(a);break;
        case C_BROWSE:choose_directory(a);break;
        case C_REKEY:{command c;memset(&c,0,sizeof c);c.type=CMD_REKEY;if(!enqueue(a,&c))set_status(a,L"换钥命令队列已满");}break;
        case C_DIR:break;
        case C_COPY_FP:copy_fingerprint(a);break;
        case C_DISCONNECT:if(a->thread)cancel_worker(a);break;
        case C_CLEAR:SetWindowTextW(a->control[C_LOG],L"");break;
        }
        return 0;
    case WM_LC_EVENT:{
        ui_event *e=(ui_event *)lp;
        if(e){switch(e->type){case EV_LOG:append_log(a,e->text);break;case EV_STATUS:set_status(a,e->text);break;
            case EV_FINGERPRINT:SetWindowTextW(a->control[C_FP],e->text);a->awaiting=1;EnableWindow(a->control[C_CONFIRM],1);EnableWindow(a->control[C_REJECT],1);break;
            case EV_READY:if(wcsstr(e->text,L"双方指纹")){a->ready=1;a->awaiting=0;update_controls(a,1,1,0);}set_status(a,e->text);break;
            case EV_PAUSE:a->ready=0;update_controls(a,a->thread?1:0,0,0);append_log(a,e->text);break;}
            ReleaseSemaphore(a->event_slots,1,NULL);free(e);}
        return 0;
    }
    case WM_LC_DONE:
        if(a->thread&&WaitForSingleObject(a->thread,2000)!=WAIT_OBJECT_0){SetTimer(hwnd,1,100,NULL);return 0;}
        if(a->thread){CloseHandle(a->thread);a->thread=NULL;}
        a->ready=0;a->awaiting=0;a->published_socket=INVALID_SOCKET;update_controls(a,0,0,0);
        if(a->closing)DestroyWindow(hwnd);
        return 0;
    case WM_TIMER:if(wp==1){finish_close_if_ready(a,hwnd);return 0;}break;
    case WM_SIZE:layout(a,LOWORD(lp),HIWORD(lp));return 0;
    case WM_GETMINMAXINFO:((MINMAXINFO *)lp)->ptMinTrackSize.x=860;((MINMAXINFO *)lp)->ptMinTrackSize.y=680;return 0;
    case WM_PAINT:{
        PAINTSTRUCT ps;HDC dc=BeginPaint(hwnd,&ps);RECT r;HBRUSH brush;int width,height;
        GetClientRect(hwnd,&r);width=r.right;height=r.bottom;brush=CreateSolidBrush(RGB(30,45,67));
        SetRect(&r,0,0,width,68);FillRect(dc,&r,brush);DeleteObject(brush);
        SetBkMode(dc,TRANSPARENT);SetTextColor(dc,RGB(255,255,255));SelectObject(dc,a->title);
        r.left=22;r.top=14;r.right=width-20;r.bottom=44;DrawTextW(dc,L"LC01 安全通信",-1,&r,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        SelectObject(dc,a->font);SetTextColor(dc,RGB(190,209,232));r.left=22;r.top=42;DrawTextW(dc,L"双向签名  ·  KEM 建钥  ·  AES-256-GCM",-1,&r,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        if(a->control[C_SOFTWARE]){
            int software=SendMessageW(a->control[C_SOFTWARE],BM_GETCHECK,0,0)==BST_CHECKED;
            r.left=width-380;r.right=width-20;r.top=21;r.bottom=49;
            SetTextColor(dc,software?RGB(255,190,92):RGB(159,221,188));
            DrawTextW(dc,software?L"软件验证 · 不访问 LC01":L"LC01 硬件 · 待现场互通验证",-1,&r,
                      DT_RIGHT|DT_VCENTER|DT_SINGLELINE);
        }
        brush=CreateSolidBrush(RGB(247,249,252));SetRect(&r,14,78,314,height-12);FillRect(dc,&r,brush);
        SetRect(&r,324,78,width-14,height-12);FillRect(dc,&r,brush);DeleteObject(brush);
        SetTextColor(dc,RGB(83,96,112));SelectObject(dc,a->font);SetBkMode(dc,TRANSPARENT);
        EndPaint(hwnd,&ps);return 0;
    }
    case WM_CTLCOLORSTATIC:{HDC dc=(HDC)wp;SetBkMode(dc,TRANSPARENT);SetTextColor(dc,RGB(44,59,78));return (LRESULT)GetSysColorBrush(COLOR_WINDOW);}
    case WM_CTLCOLOREDIT:{HDC dc=(HDC)wp;SetBkColor(dc,RGB(255,255,255));SetTextColor(dc,RGB(25,35,50));return (LRESULT)GetSysColorBrush(COLOR_WINDOW);}
    case WM_CLOSE:
        if(a->closing)return 0;
        a->closing=1;cancel_worker(a);set_status(a,L"正在停止会话并安全销毁密钥…");
        SetWindowTextW(a->control[C_STATUS],L"正在停止会话并安全销毁密钥…");
        EnableWindow(hwnd,FALSE);SetTimer(hwnd,1,100,NULL);finish_close_if_ready(a,hwnd);return 0;
    case WM_DESTROY:PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(hwnd,message,wp,lp);
}
static int create_app(app *a,HINSTANCE instance)
{
    wchar_t directory[PATH_CHARS];
    static const wchar_t *class_name=L"LC01SecureLinkMainWindow";
    WNDCLASSEXW wc;HDC dc;
    memset(a,0,sizeof *a);a->instance=instance;dc=GetDC(NULL);a->dpi=GetDeviceCaps(dc,LOGPIXELSY);ReleaseDC(NULL,dc);if(!a->dpi)a->dpi=96;
    memset(&wc,0,sizeof wc);wc.cbSize=sizeof wc;wc.lpfnWndProc=window_proc;wc.hInstance=instance;wc.lpszClassName=class_name;
    wc.hCursor=LoadCursor(NULL,IDC_ARROW);wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);wc.hIcon=LoadIcon(NULL,IDI_APPLICATION);
    if(!RegisterClassExW(&wc)&&GetLastError()!=ERROR_CLASS_ALREADY_EXISTS)return 0;
    a->font=CreateFontW(-MulDiv(10,a->dpi,72),0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
    a->title=CreateFontW(-MulDiv(20,a->dpi,72),0,0,0,FW_SEMIBOLD,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
    a->mono=CreateFontW(-MulDiv(9,a->dpi,72),0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,FIXED_PITCH,L"Consolas");
    if(!a->font||!a->title||!a->mono)return 0;
    InitializeCriticalSection(&a->lock);a->published_socket=INVALID_SOCKET;
    a->stop=CreateEventW(NULL,TRUE,FALSE,NULL);a->commands=CreateEventW(NULL,FALSE,FALSE,NULL);a->decision=CreateEventW(NULL,FALSE,FALSE,NULL);
    a->event_slots=CreateSemaphoreW(NULL,EVENT_LIMIT,EVENT_LIMIT,NULL);
    if(!a->stop||!a->commands||!a->decision||!a->event_slots)return 0;
    a->window=CreateWindowExW(WS_EX_APPWINDOW,class_name,APP_TITLE,WS_OVERLAPPEDWINDOW,100,80,1120,780,NULL,NULL,instance,a);
    if(!a->window)return 0;
    label(a,L"本端角色",C_ROLE_LABEL,0,0,0,0);child(a,L"COMBOBOX",L"",CBS_DROPDOWNLIST|WS_VSCROLL,0,C_ROLE);
    SendMessageW(a->control[C_ROLE],CB_ADDSTRING,0,(LPARAM)L"A（监听，生成本次 KEM 密钥）");SendMessageW(a->control[C_ROLE],CB_ADDSTRING,0,(LPARAM)L"B（连接，封装共享秘密）");SendMessageW(a->control[C_ROLE],CB_SETCURSEL,0,0);
    label(a,L"对端 IPv4（A 忽略此字段）",C_IP_LABEL,0,0,0,0);child(a,L"EDIT",L"127.0.0.1",ES_AUTOHSCROLL|WS_TABSTOP,WS_EX_CLIENTEDGE,C_IP);
    label(a,L"TCP 端口",C_PORT_LABEL,0,0,0,0);child(a,L"EDIT",L"44700",ES_NUMBER|ES_AUTOHSCROLL|WS_TABSTOP,WS_EX_CLIENTEDGE,C_PORT);
    child(a,L"BUTTON",L"软件验证（无板；真实软 PQC）",BS_AUTOCHECKBOX|WS_TABSTOP,0,C_SOFTWARE);SendMessageW(a->control[C_SOFTWARE],BM_SETCHECK,BST_CHECKED,0);
    label(a,L"本机 LC01 串口",C_COM_LABEL,0,0,0,0);child(a,L"COMBOBOX",L"",CBS_DROPDOWNLIST|WS_VSCROLL,0,C_COM);
    child(a,L"BUTTON",L"刷新",BS_PUSHBUTTON|WS_TABSTOP,0,C_REFRESH);
    label(a,L"串口波特率",C_BAUD_LABEL,0,0,0,0);child(a,L"EDIT",L"38580",ES_NUMBER|ES_AUTOHSCROLL|WS_TABSTOP,WS_EX_CLIENTEDGE,C_BAUD);
    child(a,L"BUTTON",L"连接并建立会话",BS_PUSHBUTTON|WS_TABSTOP,0,C_CONNECT);
    label(a,L"会话指纹（双方核对）",C_FP_LABEL,0,0,0,0);child(a,L"STATIC",L"",SS_LEFT|SS_SUNKEN,WS_EX_CLIENTEDGE,C_FP);set_font(a,a->control[C_FP],a->mono);
    child(a,L"BUTTON",L"确认一致",BS_PUSHBUTTON|WS_TABSTOP,0,C_CONFIRM);child(a,L"BUTTON",L"拒绝",BS_PUSHBUTTON|WS_TABSTOP,0,C_REJECT);
    child(a,L"BUTTON",L"复制指纹",BS_PUSHBUTTON|WS_TABSTOP,0,C_COPY_FP);
    child(a,L"STATIC",L"软件验证不访问 LC01；硬件模式需选择 COM 并使用相同波特率。",SS_LEFT,0,C_HINT);
    child(a,L"STATIC",L"等待连接",SS_LEFT|SS_CENTERIMAGE,0,C_STATUS);
    child(a,L"BUTTON",L"清空记录",BS_PUSHBUTTON|WS_TABSTOP,0,C_CLEAR);child(a,L"BUTTON",L"断开",BS_PUSHBUTTON|WS_TABSTOP,0,C_DISCONNECT);
    child(a,L"EDIT",L"",ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL|WS_TABSTOP,WS_EX_CLIENTEDGE,C_LOG);set_font(a,a->control[C_LOG],a->mono);
    a->log_proc=(WNDPROC)SetWindowLongPtrW(a->control[C_LOG],GWLP_WNDPROC,(LONG_PTR)protected_log_proc);
    child(a,L"EDIT",L"",ES_AUTOHSCROLL|WS_TABSTOP,WS_EX_CLIENTEDGE,C_INPUT);
    child(a,L"BUTTON",L"发送",BS_PUSHBUTTON|WS_TABSTOP,0,C_SEND);
    child(a,L"BUTTON",L"选择文件",BS_PUSHBUTTON|WS_TABSTOP,0,C_FILE);child(a,L"BUTTON",L"重新建钥",BS_PUSHBUTTON|WS_TABSTOP,0,C_REKEY);
    child(a,L"EDIT",L"",ES_AUTOHSCROLL,WS_EX_CLIENTEDGE,C_DIR);
    child(a,L"STATIC",L"接收目录",SS_LEFT|SS_CENTERIMAGE,0,C_DIR_LABEL);child(a,L"BUTTON",L"浏览",BS_PUSHBUTTON|WS_TABSTOP,0,C_BROWSE);
    if(SUCCEEDED(SHGetFolderPathW(NULL,CSIDL_LOCAL_APPDATA|CSIDL_FLAG_CREATE,NULL,SHGFP_TYPE_CURRENT,directory))) {
        wcscat(directory,L"\\LC01_Secure_Link\\Received");SetWindowTextW(a->control[C_DIR],directory);
    }
    SendMessageW(a->control[C_LOG],EM_SETLIMITTEXT,512000,0);
    update_controls(a,0,0,0);refresh_ports(a);layout(a,1120,780);
    return 1;
}
static void destroy_app(app *a)
{
    if(a->control[C_LOG])SetWindowTextW(a->control[C_LOG],L"");
    if(a->thread){cancel_worker(a);WaitForSingleObject(a->thread,INFINITE);CloseHandle(a->thread);a->thread=NULL;}
    if(a->stop)CloseHandle(a->stop);
    if(a->commands)CloseHandle(a->commands);
    if(a->decision)CloseHandle(a->decision);
    if(a->event_slots)CloseHandle(a->event_slots);
    if(a->font)DeleteObject(a->font);
    if(a->title)DeleteObject(a->title);
    if(a->mono)DeleteObject(a->mono);
    DeleteCriticalSection(&a->lock);
}
int lc_gui_run(HINSTANCE instance,int show)
{
    app a;MSG message;int result;
    if(!create_app(&a,instance))return 1;
    ShowWindow(a.window,show);UpdateWindow(a.window);
    while((result=GetMessageW(&message,NULL,0,0))>0){if(!IsDialogMessageW(a.window,&message)){TranslateMessage(&message);DispatchMessageW(&message);}}
    destroy_app(&a);return result<0?1:0;
}
int lc_gui_smoke(void)
{
    app a;MSG message;DWORD started;int code=1;
    if(!create_app(&a,GetModuleHandleW(NULL)))return 1;
    ShowWindow(a.window,SW_SHOWNOACTIVATE);UpdateWindow(a.window);
    PostMessageW(a.window,WM_CLOSE,0,0);started=GetTickCount64();
    while(GetTickCount64()-started<5000&&GetMessageW(&message,NULL,0,0)>0){TranslateMessage(&message);DispatchMessageW(&message);}
    if(!IsWindow(a.window)){destroy_app(&a);code=0;}
    return code;
}
