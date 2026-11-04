/* Explicit CLI-only integration harness. No GUI approval policy lives here. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "integration.h"
#include "session.h"
#include "crypto.h"

enum { IT_NONE, IT_SIGNATURE, IT_FINISH, IT_CONFIRM, IT_RECORD, IT_CT, IT_MODE };
enum { IT_HANDSHAKE = 1, IT_APPROVE, IT_TRAFFIC };
#define IT_FILE_BYTES (3u * LC_BLOCK + 137u)
#define IT_CONTROL_TAG 0x52454a31u

typedef struct {
    SOCKET socket;
    int role, fault, injected, peer_rejected, network_failed;
    unsigned last_hs_rx, pending_hs_tx;
    size_t pending_rx, pending_tx;
} it_transport;

static const char *const it_fault_names[] = {
    "none", "signature", "finish", "confirm", "record", "ct", "mode"
};

static const char *it_stage_name(int stage)
{
    return stage == IT_HANDSHAKE ? "handshake" : stage == IT_APPROVE ? "confirm" : "record";
}

static int it_fault_stage(int fault)
{
    return fault == IT_CONFIRM ? IT_APPROVE : fault == IT_RECORD ? IT_TRAFFIC : IT_HANDSHAKE;
}

static int it_net_error(it_transport *t, char *err, const char *what)
{
    char message[LC_ERR_MAX];
    t->network_failed = 1;
    (void)snprintf(message, sizeof message, "%s (WSA=%d)", what, WSAGetLastError());
    return lc_error(err, message);
}

/* All sockets are nonblocking. One absolute deadline covers every partial
 * transfer, including a slow peer sending a byte at a time. */
static int it_wait(SOCKET socket, int writing, ULONGLONG deadline, char *err)
{
    fd_set set, errors;
    struct timeval timeout;
    ULONGLONG now = GetTickCount64(), remaining;
    int result;
    if (now >= deadline) return lc_error(err, "network deadline expired");
    remaining = deadline - now;
    timeout.tv_sec = (long)(remaining / 1000u);
    timeout.tv_usec = (long)((remaining % 1000u) * 1000u);
    FD_ZERO(&set);
    FD_ZERO(&errors);
    FD_SET(socket, &set);
    FD_SET(socket, &errors);
    result = select(0, writing ? NULL : &set, writing ? &set : NULL, &errors, &timeout);
    if (result == 0) return lc_error(err, "network deadline expired");
    if (result == SOCKET_ERROR || FD_ISSET(socket, &errors))
        return lc_error(err, "network select failed");
    return 1;
}

static int it_exact(it_transport *t, uint8_t *out, const uint8_t *in,
                    size_t n, int writing, ULONGLONG deadline, char *err)
{
    size_t done = 0;
    while (done < n) {
        size_t left = n - done;
        int amount, transferred;
        if (!it_wait(t->socket, writing, deadline, err)) {
            t->network_failed = 1;
            return 0;
        }
        amount = left > (size_t)INT_MAX ? INT_MAX : (int)left;
        transferred = writing ? send(t->socket, (const char *)in + done, amount, 0)
                              : recv(t->socket, (char *)out + done, amount, 0);
        if (transferred == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINTR) continue;
            return it_net_error(t, err, writing ? "socket write failed" : "socket read failed");
        }
        if (!transferred) {
            t->network_failed = 1;
            return lc_error(err, "network EOF before exact transfer completed");
        }
        done += (size_t)transferred;
    }
    return 1;
}

static void it_control(uint8_t out[12], const char magic[4], int fault)
{
    memcpy(out, magic, 4);
    out[4] = (uint8_t)fault;
    out[5] = (uint8_t)it_fault_stage(fault);
    out[6] = 0;
    out[7] = 1;
    lc_put32(out + 8, IT_CONTROL_TAG);
}

/* The test-only rejection notification carries only a fault/stage code.
 * It is consumed exclusively by the injecting endpoint, outside the protocol.
 * EOF, timeout, and arbitrary malformed frames never count as notification. */
static int it_read(void *ctx, uint8_t *data, size_t n, char *err)
{
    it_transport *t = (it_transport *)ctx;
    ULONGLONG deadline = GetTickCount64() + 10000u;
    if (!t->pending_rx && (n == 12u || n == 35u)) {
        uint8_t expected[12];
        if (!it_exact(t, data, NULL, 12, 0, deadline, err)) return 0;
        if (!memcmp(data, "LCT0", 4)) {
            it_control(expected, "LCT0", t->fault);
            if (t->role != 1 || t->fault == IT_NONE || !t->injected ||
                !lc_equal(data, expected, sizeof expected))
                return lc_error(err, "invalid integration rejection notification");
            t->peer_rejected = 1;
            return lc_error(err, "integration peer validated expected rejection");
        }
        if (n > 12u && !it_exact(t, data + 12, NULL, n - 12u, 0, deadline, err)) return 0;
        if (n == 12u && !memcmp(data, "LCH0", 4)) {
            t->last_hs_rx = data[4];
            t->pending_rx = lc_get32(data + 8);
        }
        return 1;
    }
    if (!it_exact(t, data, NULL, n, 0, deadline, err)) return 0;
    if (t->pending_rx) {
        if (n > t->pending_rx) return lc_error(err, "integration handshake read accounting failed");
        t->pending_rx -= n;
    }
    return 1;
}

static int it_write(void *ctx, const uint8_t *data, size_t n, char *err)
{
    it_transport *t = (it_transport *)ctx;
    uint8_t modified[LC_FRAME_MAX + 64u];
    const uint8_t *wire = data;
    int inject = 0;
    if (t->pending_tx) {
        unsigned target = t->fault == IT_SIGNATURE ? 4u : t->fault == IT_FINISH ? 5u :
                          t->fault == IT_CONFIRM ? 6u : t->fault == IT_CT ? 3u : 0u;
        if (n > t->pending_tx) return lc_error(err, "integration handshake write accounting failed");
        if (t->role == 1 && !t->injected && target && t->pending_hs_tx == target && n) {
            if (n > sizeof modified) return lc_error(err, "integration fault buffer exceeded");
            memcpy(modified, data, n);
            modified[n / 2u] ^= 1u;
            wire = modified;
            inject = 1;
        }
        t->pending_tx -= n;
    } else if (n == 12u && !memcmp(data, "LCH0", 4)) {
        t->pending_hs_tx = data[4];
        t->pending_tx = lc_get32(data + 8);
        if (t->role == 1 && t->fault == IT_MODE && !t->injected) {
            memcpy(modified, data, n);
            modified[5] ^= 1u;
            wire = modified;
            inject = 1;
        }
    } else if (t->role == 1 && t->fault == IT_RECORD && !t->injected &&
               n >= 51u && !memcmp(data, "LCR0", 4)) {
        if (n > sizeof modified) return lc_error(err, "integration record buffer exceeded");
        memcpy(modified, data, n);
        modified[n - 1u] ^= 1u;
        wire = modified;
        inject = 1;
    }
    if (!it_exact(t, NULL, wire, n, 1, GetTickCount64() + 10000u, err)) return 0;
    if (inject) {
        t->injected = 1;
        printf("INJECTED role=1 fault=%s\n", it_fault_names[t->fault]);
    }
    return 1;
}

static int it_nonblocking(SOCKET socket, char *err)
{
    u_long value = 1;
    if (ioctlsocket(socket, FIONBIO, &value) == SOCKET_ERROR)
        return lc_error(err, "cannot configure nonblocking socket");
    return 1;
}

static SOCKET it_connect(int role, unsigned port, char *err)
{
    struct sockaddr_in address;
    SOCKET socket = INVALID_SOCKET, listener = INVALID_SOCKET;
    BOOL option = TRUE;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((u_short)port);
    if (role == 0) {
        listener = socket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
        if (listener == INVALID_SOCKET) goto fail;
        if (setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&option, sizeof option) == SOCKET_ERROR ||
            !it_nonblocking(listener, err) ||
            bind(listener, (const struct sockaddr *)&address, sizeof address) == SOCKET_ERROR ||
            listen(listener, 1) == SOCKET_ERROR) goto fail;
        printf("LISTENING role=0 port=%u\n", port);
        if (!it_wait(listener, 0, GetTickCount64() + 15000u, err)) goto fail;
        socket = accept(listener, NULL, NULL);
        closesocket(listener);
        listener = INVALID_SOCKET;
        if (socket == INVALID_SOCKET || !it_nonblocking(socket, err)) goto fail;
    } else {
        ULONGLONG deadline = GetTickCount64() + 10000u;
        for (;;) {
            int result, status = 0, length = (int)sizeof status;
            socket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
            if (socket == INVALID_SOCKET || !it_nonblocking(socket, err)) goto fail;
            result = connect(socket, (const struct sockaddr *)&address, sizeof address);
            if (!result) break;
            status = WSAGetLastError();
            if (status == WSAEWOULDBLOCK || status == WSAEINPROGRESS) {
                fd_set writes, errors;
                struct timeval delay;
                ULONGLONG now = GetTickCount64(), remaining;
                if (now >= deadline) goto fail;
                remaining = deadline - now;
                delay.tv_sec = (long)(remaining / 1000u);
                delay.tv_usec = (long)((remaining % 1000u) * 1000u);
                FD_ZERO(&writes); FD_ZERO(&errors);
                FD_SET(socket, &writes); FD_SET(socket, &errors);
                result = select(0, NULL, &writes, &errors, &delay);
                if (result <= 0 || getsockopt(socket, SOL_SOCKET, SO_ERROR, (char *)&status, &length) == SOCKET_ERROR) goto fail;
                if (!status) break;
            }
            closesocket(socket);
            socket = INVALID_SOCKET;
            if (status != WSAECONNREFUSED || GetTickCount64() >= deadline) goto fail;
            Sleep(25);
        }
    }
    if (setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (const char *)&option, sizeof option) == SOCKET_ERROR) goto fail;
    return socket;
fail:
    if (socket != INVALID_SOCKET && socket != listener) closesocket(socket);
    if (listener != INVALID_SOCKET) closesocket(listener);
    if (!err[0]) (void)lc_error(err, "loopback listen/connect failed");
    return INVALID_SOCKET;
}

static void it_log(void *ctx, const char *message)
{
    const it_transport *t = (const it_transport *)ctx;
    printf("STAGE role=%d %s\n", t->role, message);
}

/* Exact backend/validation errors plus the last received handshake type prevent
 * early device failures or network failures from masquerading as tamper tests.
 * CT corruption is rejected by the transcript signature, before Finished. */
static int it_local_rejected(const it_transport *t, const lc_session *s,
                             int stage, const char *err)
{
    if (t->role != 0 || t->network_failed || s->ready || s->confirmed ||
        stage != it_fault_stage(t->fault)) return 0;
    switch (t->fault) {
    case IT_SIGNATURE:
    case IT_CT:
        return t->last_hs_rx == 4u && !strcmp(err, "ML-DSA-44 signature verification failed");
    case IT_FINISH:
        return t->last_hs_rx == 5u && !strcmp(err, "shared secret confirmation rejected");
    case IT_CONFIRM:
        return t->last_hs_rx == 6u && !strcmp(err, "peer fingerprint confirmation failed");
    case IT_RECORD:
        return !strcmp(err, "record authentication failed; plaintext rejected");
    case IT_MODE:
        return t->last_hs_rx == 1u && !strcmp(err, "unexpected handshake frame / mode / role");
    default:
        return 0;
    }
}

static int it_negative_result(it_transport *t, lc_session *s, int stage, char *err)
{
    uint8_t notification[12], ack[12], received[12], drain[LC_FRAME_MAX];
    int expected_stage = it_fault_stage(t->fault);
    it_control(notification, "LCT0", t->fault);
    it_control(ack, "LCA0", t->fault);
    if (t->role == 0) {
        if (!it_local_rejected(t, s, stage, err)) return 0;
        printf("REJECTION_DETAIL role=0 fault=%s reason=%s\n", it_fault_names[t->fault], err);
        /* Mode mismatch rejects the header before reading its public payload.
         * Drain precisely that pending payload before expecting the test ACK. */
        if (t->pending_rx > sizeof drain) return lc_error(err, "invalid pending rejection payload");
        if (t->pending_rx && !it_exact(t, drain, NULL, t->pending_rx, 0, GetTickCount64() + 10000u, err)) return 0;
        t->pending_rx = 0;
        if (!it_exact(t, NULL, notification, sizeof notification, 1, GetTickCount64() + 10000u, err) ||
            !it_exact(t, received, NULL, sizeof received, 0, GetTickCount64() + 10000u, err) ||
            !lc_equal(received, ack, sizeof ack))
            return lc_error(err, "negative test peer acknowledgement failed");
    } else {
        if (!t->peer_rejected || !t->injected || t->network_failed)
            return lc_error(err, "no validated rejection from peer after injection");
        if (!it_exact(t, NULL, ack, sizeof ack, 1, GetTickCount64() + 10000u, err)) return 0;
    }
    printf("EXPECTED_REJECTION role=%d fault=%s stage=%s evidence=%s\n",
           t->role, it_fault_names[t->fault], it_stage_name(expected_stage),
           t->role == 0 ? "local-validation" : "peer-validated");
    return 1;
}

static int it_expect(lc_session *s, lc_io *io, uint8_t expected_type,
                     const uint8_t *expected, size_t expected_n, char *err)
{
    uint8_t data[LC_BLOCK], type = 0;
    size_t n = 0;
    if (!lc_record_receive(s, io, &type, data, sizeof data, &n, err)) return 0;
    if (type != expected_type || n != expected_n || !lc_equal(data, expected, n))
        return lc_error(err, "unexpected authenticated test record");
    return 1;
}

static int it_text(lc_session *s, lc_io *io, int role, int round, char *err)
{
    char from_a[96], from_b[96];
    const uint8_t *a = (const uint8_t *)from_a, *b = (const uint8_t *)from_b;
    size_t an, bn;
    (void)snprintf(from_a, sizeof from_a, "endpoint 0 -> endpoint 1: authenticated text, round %d", round);
    (void)snprintf(from_b, sizeof from_b, "endpoint 1 -> endpoint 0: authenticated reply, round %d", round);
    an = strlen(from_a); bn = strlen(from_b);
    if (role == 0) {
        if (!lc_record_send(s, io, LC_TEXT, a, an, err) ||
            !it_expect(s, io, LC_ACK, a, an, err) ||
            !it_expect(s, io, LC_TEXT, b, bn, err) ||
            !lc_record_send(s, io, LC_ACK, b, bn, err)) return 0;
    } else {
        if (!it_expect(s, io, LC_TEXT, a, an, err) ||
            !lc_record_send(s, io, LC_ACK, a, an, err) ||
            !lc_record_send(s, io, LC_TEXT, b, bn, err) ||
            !it_expect(s, io, LC_ACK, b, bn, err)) return 0;
    }
    printf("TEXT_OK role=%d round=%d bidirectional=1 ack=1\n", role, round);
    return 1;
}

static void it_file_block(uint8_t *out, size_t offset, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        size_t position = offset + i;
        out[i] = (uint8_t)(position * 73u + (position >> 4) + 19u);
    }
}

/* A deterministic virtual file avoids filesystem dependencies while exercising
 * the real begin/chunk/end record stream and independent incremental hashing. */
static int it_file(lc_session *s, lc_io *io, int role, int sender, char *err)
{
    static const char expected_hex[] = "27cb20fc5c351a6063bc58aaf585a0d26f696d23d04f894d23668ef535d6c478";
    uint8_t begin[40] = {0}, data[LC_BLOCK], expected[LC_BLOCK], digest[32], known[32];
    char hex[65];
    size_t offset = 0;
    void *hash = NULL;
    int ok = 0;
    lc_put64(begin, IT_FILE_BYTES);
    memcpy(begin + 8, "deterministic-integration.bin", 29);
    if (!lc_unhex(expected_hex, known, sizeof known)) return lc_error(err, "invalid fixed file digest");
    hash = lc_hash_new();
    if (!hash) return lc_error(err, "file hash allocation failed");
    if (role == sender) {
        if (!lc_record_send(s, io, LC_FILE_BEGIN, begin, sizeof begin, err)) goto done;
    } else if (!it_expect(s, io, LC_FILE_BEGIN, begin, sizeof begin, err)) goto done;
    while (offset < IT_FILE_BYTES) {
        size_t n = IT_FILE_BYTES - offset;
        if (n > LC_BLOCK) n = LC_BLOCK;
        it_file_block(expected, offset, n);
        if (role == sender) {
            memcpy(data, expected, n);
            if (!lc_record_send(s, io, LC_FILE_CHUNK, data, n, err)) goto done;
        } else {
            uint8_t type = 0;
            size_t got = 0;
            if (!lc_record_receive(s, io, &type, data, sizeof data, &got, err)) goto done;
            if (type != LC_FILE_CHUNK || got != n || !lc_equal(data, expected, n)) {
                (void)lc_error(err, "file chunk content/order/length mismatch"); goto done;
            }
        }
        if (!lc_hash_update(hash, data, n)) { (void)lc_error(err, "file SHA-256 update failed"); goto done; }
        offset += n;
    }
    ok = lc_hash_final(hash, digest); hash = NULL;
    if (!ok || !lc_equal(digest, known, sizeof digest)) {
        (void)lc_error(err, "deterministic file SHA-256 mismatch"); ok = 0; goto done;
    }
    ok = 0;
    if (role == sender) {
        if (!lc_record_send(s, io, LC_FILE_END, digest, sizeof digest, err) ||
            !it_expect(s, io, LC_ACK, digest, sizeof digest, err)) goto done;
    } else {
        if (!it_expect(s, io, LC_FILE_END, digest, sizeof digest, err) ||
            !lc_record_send(s, io, LC_ACK, digest, sizeof digest, err)) goto done;
    }
    lc_hex(digest, sizeof digest, hex);
    printf("FILE_OK role=%d direction=%d-to-%d bytes=%u sha256=%s\n",
           role, sender, !sender, (unsigned)IT_FILE_BYTES, hex);
    ok = 1;
done:
    lc_hash_free(hash);
    return ok;
}

static int it_handshake(lc_session *s, lc_device *device, lc_io *io,
                        it_transport *t, int round, int *stage, char *err)
{
    lc_hooks hooks = {NULL, it_log, t};
    *stage = IT_HANDSHAKE;
    if (!lc_handshake(s, device, io, t->role, hooks, err)) return 0;
    printf("FINGERPRINT role=%d round=%d fingerprint=%s\n", t->role, round, s->fingerprint);
    /* This opt-in test CLI is the sole auto-approval path. */
    printf("TEST_ONLY_AUTO_APPROVE role=%d round=%d\n", t->role, round);
    *stage = IT_APPROVE;
    if (!lc_session_confirm(s, io, 1, err)) return 0;
    printf("HANDSHAKE_OK role=%d round=%d fingerprint=%s\n", t->role, round, s->fingerprint);
    return 1;
}

static int it_endpoint(lc_device *device, lc_session *s, lc_io *io,
                       it_transport *t, char *err)
{
    int stage = IT_HANDSHAKE;
    char first_fingerprint[65];
    if (!it_handshake(s, device, io, t, 1, &stage, err))
        return t->fault != IT_NONE && it_negative_result(t, s, stage, err);
    if (t->fault != IT_NONE) {
        uint8_t data[LC_BLOCK], type = 0;
        size_t n = 0;
        stage = IT_TRAFFIC;
        if (t->fault == IT_RECORD && t->role == 1 &&
            !lc_record_send(s, io, LC_TEXT, (const uint8_t *)"tamper probe", 12, err)) return 0;
        /* A role1 Finished/Accept sender may complete its local operation
         * before role0 rejects it. Receive the explicit rejection next. */
        if (lc_record_receive(s, io, &type, data, sizeof data, &n, err))
            return lc_error(err, "negative test unexpectedly delivered authenticated plaintext");
        if (n != 0u) return lc_error(err, "rejected record published plaintext length");
        return it_negative_result(t, s, stage, err);
    }
    memcpy(first_fingerprint, s->fingerprint, sizeof first_fingerprint);
    if (!it_text(s, io, t->role, 1, err) ||
        !it_file(s, io, t->role, 0, err) || !it_file(s, io, t->role, 1, err)) return 0;
    /* Explicit authenticated rendezvous prevents mixing old traffic and the
     * next handshake. The same two independent devices establish a fresh K. */
    if (t->role == 0) {
        if (!lc_record_send(s, io, LC_REKEY_REQUEST, NULL, 0, err) ||
            !it_expect(s, io, LC_REKEY_START, NULL, 0, err)) return 0;
    } else {
        if (!it_expect(s, io, LC_REKEY_REQUEST, NULL, 0, err) ||
            !lc_record_send(s, io, LC_REKEY_START, NULL, 0, err)) return 0;
    }
    lc_session_close(s);
    if (!it_handshake(s, device, io, t, 2, &stage, err)) return 0;
    if (!strcmp(first_fingerprint, s->fingerprint)) return lc_error(err, "rehandshake fingerprint unchanged");
    printf("REKEY_OK role=%d fingerprint_changed=1\n", t->role);
    if (!it_text(s, io, t->role, 2, err)) return 0;
    if (t->role == 0) {
        if (!lc_record_send(s, io, LC_CLOSE, NULL, 0, err) ||
            !it_expect(s, io, LC_ACK, NULL, 0, err)) return 0;
    } else if (!it_expect(s, io, LC_CLOSE, NULL, 0, err) ||
               !lc_record_send(s, io, LC_ACK, NULL, 0, err)) return 0;
    return 1;
}

int lc_integration_run(int argc, char **argv)
{
    WSADATA wsa;
    it_transport transport;
    lc_session session;
    lc_device_config config;
    lc_device *device = NULL;
    lc_io io;
    char err[LC_ERR_MAX] = {0}, *end = NULL;
    unsigned long port;
    int fault, result = 1;
    (void)setvbuf(stdout, NULL, _IONBF, 0);
    (void)setvbuf(stderr, NULL, _IONBF, 0);
    if (argc != 5 || strcmp(argv[1], "--test-endpoint") ||
        (strcmp(argv[2], "0") && strcmp(argv[2], "1"))) {
        fprintf(stderr, "usage: --test-endpoint <0|1> <1..65535> <none|signature|finish|confirm|record|ct|mode>\n");
        return 2;
    }
    if (!argv[3][0] || strspn(argv[3], "0123456789") != strlen(argv[3])) {
        fprintf(stderr, "FAIL invalid decimal port\n"); return 2;
    }
    port = strtoul(argv[3], &end, 10);
    if (!end || *end || !port || port > 65535ul) {
        fprintf(stderr, "FAIL invalid port\n"); return 2;
    }
    for (fault = IT_NONE; fault <= IT_MODE; ++fault)
        if (!strcmp(argv[4], it_fault_names[fault])) break;
    if (fault > IT_MODE) { fprintf(stderr, "FAIL invalid fault\n"); return 2; }
    memset(&transport, 0, sizeof transport);
    memset(&session, 0, sizeof session);
    memset(&config, 0, sizeof config);
    transport.socket = INVALID_SOCKET;
    transport.role = argv[2][0] - '0';
    transport.fault = fault;
    io.ctx = &transport; io.read = it_read; io.write = it_write;
    config.mode = LC_SOFTWARE;
    config.timeout_ms = 10000;
    config.hooks.ctx = &transport; config.hooks.log = it_log;
    if (WSAStartup(MAKEWORD(2, 2), &wsa)) {
        fprintf(stderr, "FAIL WSAStartup\n"); return 1;
    }
    device = lc_device_open(&config, err);
    if (!device) goto done;
    if (lc_device_mode(device) != LC_SOFTWARE) {
        (void)lc_error(err, "integration requires independent software PQC device"); goto done;
    }
    printf("DEVICE role=%d mode=software algorithms=%s\n", transport.role, lc_device_algorithms(device));
    transport.socket = it_connect(transport.role, (unsigned)port, err);
    if (transport.socket == INVALID_SOCKET) goto done;
    if (!it_endpoint(device, &session, &io, &transport, err)) goto done;
    printf("PASS role=%d fault=%s\n", transport.role, it_fault_names[fault]);
    result = 0;
done:
    if (result) fprintf(stderr, "FAIL role=%d fault=%s reason=%s\n", transport.role, it_fault_names[fault], err[0] ? err : "unexpected integration failure");
    lc_session_close(&session);
    lc_device_close(device);
    if (transport.socket != INVALID_SOCKET) closesocket(transport.socket);
    (void)WSACleanup();
    return result;
}
