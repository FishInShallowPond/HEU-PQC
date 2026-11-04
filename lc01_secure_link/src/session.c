#include "session.h"
#include "crypto.h"
#include <string.h>
#include <stdio.h>

enum { HS_HELLO=1,HS_PK=2,HS_CT=3,HS_SIG=4,HS_FINISH=5,HS_ACCEPT=6 };
static int hs_send(lc_io *io,int mode,int role,uint8_t type,const uint8_t *p,size_t n,char *err)
{
    uint8_t h[12]={'L','C','H','0',0,0,0,0,0,0,0,0};
    if(n>LC_FRAME_MAX)return lc_error(err,"handshake frame too large");
    h[4]=type;h[5]=(uint8_t)mode;h[6]=(uint8_t)role;lc_put32(h+8,(uint32_t)n);
    return io->write(io->ctx,h,sizeof h,err) && (!n||io->write(io->ctx,p,n,err));
}
static int hs_read(lc_io *io,int mode,int peer,uint8_t type,uint8_t *p,size_t cap,size_t *n,char *err)
{
    uint8_t h[12];
    if(!io->read(io->ctx,h,sizeof h,err))return 0;
    if(memcmp(h,"LCH0",4)||h[4]!=type||h[5]!=mode||h[6]!=peer||h[7])
        return lc_error(err,"unexpected handshake frame / mode / role");
    *n=lc_get32(h+8);
    if(*n>cap||*n>LC_FRAME_MAX)return lc_error(err,"invalid handshake length");
    return !*n||io->read(io->ctx,p,*n,err);
}
static int hash_piece(void *h,const uint8_t *p,size_t n)
{
    uint8_t length[4];lc_put32(length,(uint32_t)n);
    return lc_hash_update(h,length,4)&&lc_hash_update(h,p,n);
}
static int binding_digest(int mode,const uint8_t *a,size_t an,const uint8_t *b,size_t bn,
 const uint8_t *pk,size_t pn,const uint8_t *ct,size_t cn,uint8_t out[32])
{
    static const char domain[]="LC01-Secure-Link-v0/mutual-kem-binding";
    uint8_t m=(uint8_t)mode;void *h=lc_hash_new();
    if(!h)return 0;
    if(!hash_piece(h,(const uint8_t *)domain,sizeof domain-1)||!hash_piece(h,&m,1)||
       !hash_piece(h,a,an)||!hash_piece(h,b,bn)||!hash_piece(h,pk,pn)||!hash_piece(h,ct,cn)) {
        lc_hash_free(h);return 0;
    }
    return lc_hash_final(h,out);
}
static int proof_message(int role,const uint8_t digest[32],uint8_t out[33])
{
    uint8_t input[64]={0};
    static const char domain[]="LC01-v0/signature/";
    memcpy(input,domain,sizeof domain-1);input[sizeof domain-1]=(uint8_t)role;
    memcpy(input+sizeof domain,digest,32);out[0]=0x31;
    return lc_sha256(input,sizeof domain+32,out+1);
}
static int derive_session(lc_session *s,const uint8_t secret[32],const uint8_t transcript[32],int role,int mode)
{
    uint8_t material[72],info[64]={0};
    static const char label[]="LC01-v0/directional-key-schedule";
    memcpy(info,label,sizeof label-1);memcpy(info+sizeof label-1,transcript,32);
    if(!lc_hkdf(secret,32,transcript,32,info,sizeof label-1+32,material,sizeof material))return 0;
    memset(s,0,sizeof *s);s->role=role;s->mode=mode;
    memcpy(s->transcript,transcript,32);memcpy(s->sid,transcript,16);memcpy(s->local_k,secret,32);
    memcpy(s->tx_key,material+(role?36:0),32);memcpy(s->rx_key,material+(role?0:36),32);
    memcpy(s->tx_prefix,material+(role?68:32),4);memcpy(s->rx_prefix,material+(role?32:68),4);
    lc_hex(transcript,32,s->fingerprint);
    lc_zero(material,sizeof material);return 1;
}
static int confirmation_token(const uint8_t secret[32],const uint8_t transcript[32],int role,
                             int purpose,uint8_t result[32])
{
    uint8_t key[32],info[64]={0},message[36];
    const char *label=purpose?"LC01-v0/user-confirm":"LC01-v0/finished";
    size_t n=strlen(label);memcpy(info,label,n);info[n]=(uint8_t)role;
    memcpy(message,transcript,32);message[32]=(uint8_t)role;message[33]=(uint8_t)purpose;
    message[34]=0;message[35]=1;
    if(!lc_hkdf(secret,32,transcript,32,info,n+1,key,32))return 0;
    int ok=lc_hmac(key,32,message,sizeof message,result);lc_zero(key,sizeof key);return ok;
}
static int exchange_confirmation(lc_io *io,int mode,int role,uint8_t type,
 const uint8_t secret[32],const uint8_t transcript[32],int purpose,char *err)
{
    uint8_t token[32],received[32],expected[32];size_t n=0;int ok=0;
    if(!confirmation_token(secret,transcript,role,purpose,token)||
       !confirmation_token(secret,transcript,!role,purpose,expected)) {
        lc_error(err,"confirmation backend failed");goto done;
    }
    if(role==0 && !hs_send(io,mode,role,type,token,32,err))goto done;
    if(!hs_read(io,mode,!role,type,received,32,&n,err))goto done;
    if(n!=32||!lc_equal(received,expected,32)) {
        lc_error(err,purpose?"peer fingerprint confirmation failed":"shared secret confirmation rejected");goto done;
    }
    /* Never acknowledge an invalid peer proof, even with a valid local proof. */
    if(role==1 && !hs_send(io,mode,role,type,token,32,err))goto done;
    ok=1;
done:
    lc_zero(token,sizeof token);lc_zero(received,sizeof received);lc_zero(expected,sizeof expected);
    return ok;
}
static void log_stage(lc_hooks hooks,const char *text){if(hooks.log)hooks.log(hooks.ctx,text);}
int lc_handshake(lc_session *s,lc_device *d,lc_io *io,int role,lc_hooks hooks,char *err)
{
    uint8_t local[34+LC_PK_MAX],peer[34+LC_PK_MAX],pk[LC_PK_MAX],ct[LC_CT_MAX];
    uint8_t signature_a[LC_SIG_MAX],signature_b[LC_SIG_MAX],secret[32]={0};
    uint8_t digest[32],transcript[32],message[33];
    size_t ln=LC_PK_MAX,pn=0,kn=LC_PK_MAX,cn=LC_CT_MAX,san=LC_SIG_MAX,sbn=LC_SIG_MAX;
    int mode=lc_device_mode(d),ok=0;void *hash=NULL;
    memset(s,0,sizeof *s);
    if(role!=0&&role!=1)return lc_error(err,"invalid endpoint role");
    if(hooks.cancelled&&hooks.cancelled(hooks.ctx))return lc_error(err,"cancelled");
    log_stage(hooks,"Generating local signing key");
    if(!lc_random(local,32)||!lc_device_sign_keygen(d,local+34,&ln,err))goto done;
    if(!ln||ln>LC_PK_MAX){lc_error(err,"invalid signing public key length");goto done;}
    local[32]=(uint8_t)(ln>>8);local[33]=(uint8_t)ln;ln+=34;
    if(role==0) {
        if(!hs_send(io,mode,role,HS_HELLO,local,ln,err)||
           !hs_read(io,mode,1,HS_HELLO,peer,sizeof peer,&pn,err))goto done;
    } else {
        if(!hs_read(io,mode,0,HS_HELLO,peer,sizeof peer,&pn,err)||
           !hs_send(io,mode,role,HS_HELLO,local,ln,err))goto done;
    }
    if(pn<35||pn>sizeof peer||(((size_t)peer[32]<<8)|peer[33])!=pn-34) {
        lc_error(err,"invalid peer signing key encoding");goto done;
    }
    log_stage(hooks,"Establishing local KEM secret");
    if(role==0) {
        if(!lc_device_kem_keygen(d,pk,&kn,err)||
           !hs_send(io,mode,role,HS_PK,pk,kn,err)||
           !hs_read(io,mode,1,HS_CT,ct,sizeof ct,&cn,err)||
           !lc_device_decaps(d,ct,cn,secret,err))goto done;
    } else {
        if(!hs_read(io,mode,0,HS_PK,pk,sizeof pk,&kn,err)||
           !lc_device_encaps(d,pk,kn,ct,&cn,secret,err)||
           !hs_send(io,mode,role,HS_CT,ct,cn,err))goto done;
    }
    if(!binding_digest(mode,role?peer:local,role?pn:ln,role?local:peer,role?ln:pn,pk,kn,ct,cn,digest))goto crypto_fail;
    log_stage(hooks,"Mutual signatures over both challenges, roles and KEM transcript");
    if(role==1) {
        if(!proof_message(1,digest,message)||!lc_device_sign(d,message,signature_b,&sbn,err)||
           !hs_send(io,mode,role,HS_SIG,signature_b,sbn,err)||
           !hs_read(io,mode,0,HS_SIG,signature_a,sizeof signature_a,&san,err)||
           !proof_message(0,digest,message)||
           !lc_device_verify(d,peer+34,pn-34,message,signature_a,san,err))goto done;
    } else {
        if(!hs_read(io,mode,1,HS_SIG,signature_b,sizeof signature_b,&sbn,err)||
           !proof_message(1,digest,message)||
           !lc_device_verify(d,peer+34,pn-34,message,signature_b,sbn,err)||
           !proof_message(0,digest,message)||!lc_device_sign(d,message,signature_a,&san,err)||
           !hs_send(io,mode,role,HS_SIG,signature_a,san,err))goto done;
    }
    hash=lc_hash_new();if(!hash)goto crypto_fail;
    if(!hash_piece(hash,digest,32)||!hash_piece(hash,signature_a,san)||!hash_piece(hash,signature_b,sbn)) {
        lc_hash_free(hash);hash=NULL;goto crypto_fail;
    }
    if(!lc_hash_final(hash,transcript)){hash=NULL;goto crypto_fail;}hash=NULL;
    if(!derive_session(s,secret,transcript,role,mode))goto crypto_fail;
    if(!exchange_confirmation(io,mode,role,HS_FINISH,secret,transcript,0,err))goto done;
    s->ready=1;ok=1;
    log_stage(hooks,"Mutual signatures and key confirmation passed; verify fingerprint on independent trusted channel");
    goto done;
crypto_fail:
    lc_error(err,"cryptographic backend failed");
done:
    lc_zero(secret,sizeof secret);lc_zero(message,sizeof message);
    if(!ok){lc_session_close(s);if(err&&!err[0])lc_error(err,"handshake failed");}
    return ok;
}
int lc_session_confirm(lc_session *s,lc_io *io,int accept,char *err)
{
    int ok;
    if(!s->ready||s->confirmed)return lc_error(err,"session not awaiting confirmation");
    if(!accept){lc_session_close(s);return lc_error(err,"fingerprint rejected locally");}
    ok=exchange_confirmation(io,s->mode,s->role,HS_ACCEPT,s->local_k,s->transcript,1,err);
    if(ok)s->confirmed=1;else lc_session_close(s);
    return ok;
}
void lc_session_close(lc_session *s){if(s)lc_zero(s,sizeof *s);}
static void nonce_for(const uint8_t prefix[4],uint64_t seq,uint8_t out[12])
{memcpy(out,prefix,4);lc_put64(out+4,seq);}
int lc_record_send(lc_session *s,lc_io *io,uint8_t type,const uint8_t *data,size_t n,char *err)
{
    uint8_t packet[35+LC_BLOCK+16],nonce[12];
    if(!s->ready||!s->confirmed)return lc_error(err,"fingerprint confirmation required");
    if(n>LC_BLOCK||type<LC_TEXT||type>LC_CLOSE||(!data&&n))return lc_error(err,"invalid outbound record");
    if(s->tx_sequence>=(1u<<20)||s->tx_bytes+n>LC_SESSION_BYTES) {
        lc_session_close(s);return lc_error(err,"traffic key usage limit; rekey required");
    }
    memcpy(packet,"LCR0",4);packet[4]=0;packet[5]=type;packet[6]=(uint8_t)s->role;
    memcpy(packet+7,s->sid,16);lc_put64(packet+23,s->tx_sequence);lc_put32(packet+31,(uint32_t)n);
    nonce_for(s->tx_prefix,s->tx_sequence,nonce);
    ++s->tx_sequence;s->tx_bytes+=n;
    if(!lc_aead_seal(s->tx_key,nonce,packet,35,data,n,packet+35,packet+35+n)||
       !io->write(io->ctx,packet,35+n+16,err)) {
        lc_session_close(s);return lc_error(err,"record encrypt/send failed; delivery unknown");
    }
    return 1;
}
int lc_record_receive(lc_session *s,lc_io *io,uint8_t *type,uint8_t *data,size_t cap,size_t *n,char *err)
{
    uint8_t h[35],body[LC_BLOCK+16],nonce[12];size_t length;int ok=0;
    *n=0;
    if(!s->ready||!s->confirmed)return lc_error(err,"fingerprint confirmation required");
    if(!io->read(io->ctx,h,35,err))goto done;
    length=lc_get32(h+31);
    if(memcmp(h,"LCR0",4)||h[4]||h[5]<LC_TEXT||h[5]>LC_CLOSE||h[6]!=(uint8_t)!s->role||
       !lc_equal(h+7,s->sid,16)||lc_get64(h+23)!=s->rx_sequence||length>LC_BLOCK||length>cap||
       s->rx_sequence>=(1u<<20)||s->rx_bytes+length>LC_SESSION_BYTES) {
        lc_error(err,"record header/session/direction/sequence/length rejected");goto done;
    }
    if(!io->read(io->ctx,body,length+16,err))goto done;
    nonce_for(s->rx_prefix,s->rx_sequence,nonce);
    if(!lc_aead_open(s->rx_key,nonce,h,35,body,length,body+length,data)) {
        lc_error(err,"record authentication failed; plaintext rejected");goto done;
    }
    ++s->rx_sequence;s->rx_bytes+=length;*type=h[5];*n=length;ok=1;
done:
    if(!ok){lc_zero(data,cap);lc_session_close(s);}return ok;
}

typedef struct {uint8_t bytes[35+LC_BLOCK+16];size_t used,offset;} test_pipe;
static int test_write(void *ctx,const uint8_t *p,size_t n,char *err)
{test_pipe *b=ctx;if(n>sizeof b->bytes-b->used)return lc_error(err,"test buffer full");memcpy(b->bytes+b->used,p,n);b->used+=n;return 1;}
static int test_read(void *ctx,uint8_t *p,size_t n,char *err)
{test_pipe *b=ctx;if(n>b->used-b->offset)return lc_error(err,"test EOF");memcpy(p,b->bytes+b->offset,n);b->offset+=n;return 1;}
int lc_session_selftest(char *err)
{
    lc_session a,b;uint8_t key[32]={1},tr[32]={2},out[LC_BLOCK],type;size_t n;
    test_pipe pipe;lc_io io={&pipe,test_read,test_write};
    if(!derive_session(&a,key,tr,0,LC_SOFTWARE)||!derive_session(&b,key,tr,1,LC_SOFTWARE))return lc_error(err,"derive test");
    memset(&pipe,0,sizeof pipe);
    if(lc_record_send(&a,&io,LC_TEXT,(const uint8_t *)"blocked",7,err))return lc_error(err,"unconfirmed send allowed");
    a.confirmed=b.confirmed=a.ready=b.ready=1;
    if(!lc_record_send(&a,&io,LC_TEXT,(const uint8_t *)"hello",5,err)||
       !lc_record_receive(&b,&io,&type,out,sizeof out,&n,err)||n!=5||memcmp(out,"hello",5))return lc_error(err,"roundtrip test");
    pipe.offset=0;
    if(lc_record_receive(&b,&io,&type,out,sizeof out,&n,err))return lc_error(err,"replay accepted");
    for(int fault=0;fault<7;++fault) {
        if(!derive_session(&a,key,tr,0,LC_SOFTWARE)||!derive_session(&b,key,tr,1,LC_SOFTWARE))return 0;
        a.confirmed=b.confirmed=a.ready=b.ready=1;memset(&pipe,0,sizeof pipe);
        if(!lc_record_send(&a,&io,LC_TEXT,(const uint8_t *)"hello",5,err))return 0;
        switch(fault) {
        case 0:pipe.bytes[35]^=1;break;
        case 1:pipe.bytes[pipe.used-1]^=1;break;
        case 2:pipe.bytes[6]^=1;break;
        case 3:pipe.bytes[7]^=1;break;
        case 4:pipe.bytes[30]^=1;break;
        case 5:pipe.used--;break;
        default:lc_put32(pipe.bytes+31,LC_BLOCK+1);break;
        }
        if(lc_record_receive(&b,&io,&type,out,sizeof out,&n,err)||n||b.ready)return lc_error(err,"negative record accepted");
    }
    if(!derive_session(&a,key,tr,0,LC_SOFTWARE))return 0;
    a.confirmed=a.ready=1;a.tx_sequence=(1u<<20);memset(&pipe,0,sizeof pipe);
    if(lc_record_send(&a,&io,LC_TEXT,(const uint8_t *)"x",1,err)||a.ready)return lc_error(err,"nonce limit accepted");
    /* A responder must validate the peer before emitting its success proof. */
    for(int role=0;role<2;++role)for(int purpose=0;purpose<2;++purpose)for(int fault=0;fault<3;++fault) {
        size_t length=fault==0?0u:(fault==1?31u:32u),initial;
        uint8_t frame_type=purpose?HS_ACCEPT:HS_FINISH;
        memset(&pipe,0,sizeof pipe);memset(out,0,32);
        if(!hs_send(&io,LC_SOFTWARE,!role,frame_type,out,length,err))return 0;
        initial=pipe.used;
        if(exchange_confirmation(&io,LC_SOFTWARE,role,frame_type,key,tr,purpose,err)||
           pipe.used!=initial+(role==0?44u:0u))
            return lc_error(err,"invalid confirmation accepted or acknowledged");
    }
    for(int role=0;role<2;++role)for(int purpose=0;purpose<2;++purpose) {
        uint8_t frame_type=purpose?HS_ACCEPT:HS_FINISH;
        memset(&pipe,0,sizeof pipe);
        if(!confirmation_token(key,tr,!role,purpose,out)||
           !hs_send(&io,LC_SOFTWARE,!role,frame_type,out,32,err)||
           !exchange_confirmation(&io,LC_SOFTWARE,role,frame_type,key,tr,purpose,err)||pipe.used!=88u)
            return lc_error(err,"valid confirmation rejected");
    }
    if(!derive_session(&b,key,tr,1,LC_SOFTWARE))return 0;
    b.ready=1;memset(&pipe,0,sizeof pipe);memset(out,0,32);
    if(!hs_send(&io,LC_SOFTWARE,0,HS_ACCEPT,out,32,err)||
       lc_session_confirm(&b,&io,1,err)||b.ready||pipe.used!=44u)
        return lc_error(err,"failed confirmation did not close session");
    lc_session_close(&a);lc_session_close(&b);err[0]=0;return 1;
}
