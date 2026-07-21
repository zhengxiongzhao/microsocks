/*
   MicroSocks - multithreaded, small, efficient SOCKS5 server.

   Copyright (C) 2017 rofl0r.

   This is the successor of "rocksocks5", and it was written with
   different goals in mind:

   - prefer usage of standard libc functions over homegrown ones
   - no artificial limits
   - do not aim for minimal binary size, but for minimal source code size,
     and maximal readability, reusability, and extensibility.

   as a result of that, ipv4, dns, and ipv6 is supported out of the box
   and can use the same code, while rocksocks5 has several compile time
   defines to bring down the size of the resulting binary to extreme values
   like 10 KB static linked when only ipv4 support is enabled.

   still, if optimized for size, *this* program when static linked against musl
   libc is not even 50 KB. that's easily usable even on the cheapest routers.

*/

#define _GNU_SOURCE
#include <unistd.h>
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdatomic.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include "server.h"
#include "sblist.h"

/* timeout in microseconds on resource exhaustion to prevent excessive
   cpu usage. */
#ifndef FAILURE_TIMEOUT
#define FAILURE_TIMEOUT 64
#endif

/* hard upper bound for the auth_once whitelist. without this, the list
   grows unboundedly with every distinct client IP that authenticates
   (one byte of leaked memory per IP forever), and the O(n) linear scan
   in is_in_authed_list() degrades handshake latency over time.
   65536 * sizeof(union sockaddr_union) (~28B) ~= 1.8 MiB cap.
   when full, the oldest entry is evicted (simple LRU). */
#ifndef AUTH_IPS_MAX
#define AUTH_IPS_MAX 65536
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifdef PTHREAD_STACK_MIN
#define THREAD_STACK_SIZE MAX(16*1024, PTHREAD_STACK_MIN)
#else
#define THREAD_STACK_SIZE 64*1024
#endif

#if defined(__APPLE__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 64*1024
#elif defined(__GLIBC__) || defined(__FreeBSD__) || defined(__sun__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 32*1024
#elif defined(__OpenBSD__) && defined(__clang__)
#undef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE 32*1024
#endif

static int quiet;
static const char* auth_user;
static const char* auth_pass;
static sblist* auth_ips;
static pthread_rwlock_t auth_ips_lock = PTHREAD_RWLOCK_INITIALIZER;
static const struct server* server;
static union sockaddr_union bind_addr = {.v4.sin_family = AF_UNSPEC};

/* recycle pool for struct thread, accessed only from the main thread
   (both alloc and release happen in the accept loop), so no locking
   is required. avoids per-connection malloc/free churn under load. */
static sblist* threadpool;

enum socksstate {
	SS_1_CONNECTED,
	SS_2_NEED_AUTH, /* skipped if NO_AUTH method supported */
	SS_3_AUTHED,
};

enum authmethod {
	AM_NO_AUTH = 0,
	AM_GSSAPI = 1,
	AM_USERNAME = 2,
	AM_INVALID = 0xFF
};

enum errorcode {
	EC_SUCCESS = 0,
	EC_GENERAL_FAILURE = 1,
	EC_NOT_ALLOWED = 2,
	EC_NET_UNREACHABLE = 3,
	EC_HOST_UNREACHABLE = 4,
	EC_CONN_REFUSED = 5,
	EC_TTL_EXPIRED = 6,
	EC_COMMAND_NOT_SUPPORTED = 7,
	EC_ADDRESSTYPE_NOT_SUPPORTED = 8,
};

struct thread {
	pthread_t pt;
	struct client client;
	enum socksstate state;
	/* C11 atomic: the worker thread stores 1 on exit, the main thread
	   loads it when sweeping for joinable threads. "volatile int" does
	   NOT provide a memory barrier and is a data race per the standard,
	   which can leak joined-but-undetected thread structs on weakly
	   ordered architectures (ARM, etc). */
	atomic_int done;
};

#ifndef CONFIG_LOG
#define CONFIG_LOG 1
#endif
#if CONFIG_LOG
/* we log to stderr because it's not using line buffering, i.e. malloc which would need
   locking when called from different threads. for the same reason we use dprintf,
   which writes directly to an fd. */
#define dolog(...) do { if(!quiet) dprintf(2, __VA_ARGS__); } while(0)
#else
static void dolog(const char* fmt, ...) { }
#endif

/* write exactly n bytes, retrying on EINTR and handling short writes.
   returns 0 on success, -1 on error. the original code used bare write()
   for fixed-size protocol frames, which can deliver a partial frame on a
   socket (EINTR, kernel buffer pressure) and corrupt the SOCKS5 handshake. */
static int write_all(int fd, const void *buf, size_t n) {
	const char *p = buf;
	while(n) {
		ssize_t w = write(fd, p, n);
		if(w < 0) {
			if(errno == EINTR) continue;
			return -1;
		}
		if(w == 0) return -1;
		p += w;
		n -= (size_t)w;
	}
	return 0;
}

/* map a connect/socket/bind errno to a negative SOCKS5 error code.
   taking errno by value lets the caller save it before close()/freeaddrinfo()
   clobber it (those syscalls overwrite errno even on success). */
static int errno_to_ec(int e) {
	switch(e) {
		case ETIMEDOUT:
			return -EC_TTL_EXPIRED;
		case EPROTOTYPE:
		case EPROTONOSUPPORT:
		case EAFNOSUPPORT:
			return -EC_ADDRESSTYPE_NOT_SUPPORTED;
		case ECONNREFUSED:
			return -EC_CONN_REFUSED;
		case ENETDOWN:
		case ENETUNREACH:
			return -EC_NET_UNREACHABLE;
		case EHOSTUNREACH:
			return -EC_HOST_UNREACHABLE;
		default:
			errno = e;
			perror("socket/connect");
			return -EC_GENERAL_FAILURE;
	}
}

static struct addrinfo* addr_choose(struct addrinfo* list, union sockaddr_union* bindaddr) {
	int af = SOCKADDR_UNION_AF(bindaddr);
	if(af == AF_UNSPEC) return list;
	struct addrinfo* p;
	for(p=list; p; p=p->ai_next)
		if(p->ai_family == af) return p;
	return list;
}

static int connect_socks_target(unsigned char *buf, size_t n, struct client *client) {
	if(n < 5) return -EC_GENERAL_FAILURE;
	if(buf[0] != 5) return -EC_GENERAL_FAILURE;
	if(buf[1] != 1) return -EC_COMMAND_NOT_SUPPORTED; /* we support only CONNECT method */
	if(buf[2] != 0) return -EC_GENERAL_FAILURE; /* malformed packet */

	int af = AF_INET;
	size_t minlen = 4 + 4 + 2, l;
	char namebuf[256];
	struct addrinfo* remote;

	switch(buf[3]) {
		case 4: /* ipv6 */
			af = AF_INET6;
			minlen = 4 + 2 + 16;
			/* fall through */
		case 1: /* ipv4 */
			if(n < minlen) return -EC_GENERAL_FAILURE;
			if(namebuf != inet_ntop(af, buf+4, namebuf, sizeof namebuf))
				return -EC_GENERAL_FAILURE; /* malformed or too long addr */
			break;
		case 3: /* dns name */
			l = buf[4];
			minlen = 4 + 2 + l + 1;
			if(n < 4 + 2 + l + 1) return -EC_GENERAL_FAILURE;
			memcpy(namebuf, buf+4+1, l);
			namebuf[l] = 0;
			break;
		default:
			return -EC_ADDRESSTYPE_NOT_SUPPORTED;
	}
	unsigned short port;
	port = (buf[minlen-2] << 8) | buf[minlen-1];
	/* there's no suitable errorcode in rfc1928 for dns lookup failure */
	if(resolve(namebuf, port, &remote)) return -EC_GENERAL_FAILURE;
	struct addrinfo* raddr = addr_choose(remote, &bind_addr);
	int fd = socket(raddr->ai_family, SOCK_STREAM, 0);
	/* on every failing syscall below we snapshot errno first, then close()/freeaddrinfo(),
	   then translate. the previous code jumped to a label that ran close() *before*
	   consulting errno, so the reported SOCKS5 error code was taken from close()'s
	   own errno side effect rather than the real connect/socket failure. */
	if(fd == -1) {
		int e = errno;
		freeaddrinfo(remote);
		return errno_to_ec(e);
	}
	if(SOCKADDR_UNION_AF(&bind_addr) == raddr->ai_family &&
	   bindtoip(fd, &bind_addr) == -1) {
		int e = errno;
		close(fd);
		freeaddrinfo(remote);
		return errno_to_ec(e);
	}
	if(connect(fd, raddr->ai_addr, raddr->ai_addrlen) == -1) {
		int e = errno;
		close(fd);
		freeaddrinfo(remote);
		return errno_to_ec(e);
	}

	freeaddrinfo(remote);
	if(CONFIG_LOG) {
		char clientname[256];
		af = SOCKADDR_UNION_AF(&client->addr);
		void *ipdata = SOCKADDR_UNION_ADDRESS(&client->addr);
		inet_ntop(af, ipdata, clientname, sizeof clientname);
		dolog("client[%d] %s: connected to %s:%d\n", client->fd, clientname, namebuf, port);
	}
	return fd;
}

static int is_authed(union sockaddr_union *client, union sockaddr_union *authedip) {
	int af = SOCKADDR_UNION_AF(authedip);
	if(af == SOCKADDR_UNION_AF(client)) {
		size_t cmpbytes = af == AF_INET ? 4 : 16;
		void *cmp1 = SOCKADDR_UNION_ADDRESS(client);
		void *cmp2 = SOCKADDR_UNION_ADDRESS(authedip);
		if(!memcmp(cmp1, cmp2, cmpbytes)) return 1;
	}
	return 0;
}

static int is_in_authed_list(union sockaddr_union *caddr) {
	size_t i;
	for(i=0;i<sblist_getsize(auth_ips);i++)
		if(is_authed(caddr, sblist_get(auth_ips, i)))
			return 1;
	return 0;
}

static void add_auth_ip(union sockaddr_union *caddr) {
	/* bound the whitelist to prevent unbounded memory growth and
	   unbounded O(n) scan time; evict the oldest entry (LRU) when full. */
	if(sblist_getsize(auth_ips) >= AUTH_IPS_MAX)
		sblist_delete(auth_ips, 0);
	sblist_add(auth_ips, caddr);
}

static enum authmethod check_auth_method(unsigned char *buf, size_t n, struct client*client) {
	if(buf[0] != 5) return AM_INVALID;
	size_t idx = 1;
	if(idx >= n ) return AM_INVALID;
	int n_methods = buf[idx];
	idx++;
	while(idx < n && n_methods > 0) {
		if(buf[idx] == AM_NO_AUTH) {
			if(!auth_user) return AM_NO_AUTH;
			else if(auth_ips) {
				int authed = 0;
				if(pthread_rwlock_rdlock(&auth_ips_lock) == 0) {
					authed = is_in_authed_list(&client->addr);
					pthread_rwlock_unlock(&auth_ips_lock);
				}
				if(authed) return AM_NO_AUTH;
			}
		} else if(buf[idx] == AM_USERNAME) {
			if(auth_user) return AM_USERNAME;
		}
		idx++;
		n_methods--;
	}
	return AM_INVALID;
}

static void send_auth_response(int fd, int version, enum authmethod meth) {
	unsigned char buf[2];
	buf[0] = version;
	buf[1] = meth;
	write_all(fd, buf, 2);
}

static void send_error(int fd, enum errorcode ec) {
	/* position 4 contains ATYP, the address type, which is the same as used in the connect
	   request. we're lazy and return always IPV4 address type in errors. */
	char buf[10] = { 5, ec, 0, 1 /*AT_IPV4*/, 0,0,0,0, 0,0 };
	write_all(fd, buf, 10);
}

static void copyloop(int fd1, int fd2) {
	struct pollfd fds[2] = {
		[0] = {.fd = fd1, .events = POLLIN},
		[1] = {.fd = fd2, .events = POLLIN},
	};

	while(1) {
		/* inactive connections are reaped after 15 min to free resources.
		   usually programs send keep-alive packets so this should only happen
		   when a connection is really unused. */
		switch(poll(fds, 2, 60*15*1000)) {
			case 0:
				return;
			case -1:
				if(errno == EINTR || errno == EAGAIN) continue;
				else perror("poll");
				return;
		}
		if((fds[0].revents & (POLLERR | POLLNVAL)) || (fds[1].revents & (POLLERR | POLLNVAL)))
			return;

		for(int i = 0; i < 2; i++) {
			if(fds[i].revents & (POLLIN | POLLHUP)) {
				int infd = fds[i].fd;
				int outfd = fds[1 - i].fd;
				char buf[MIN(16*1024, THREAD_STACK_SIZE/2)];
				ssize_t n = read(infd, buf, sizeof buf);
				if(n <= 0) return;
				if(write_all(outfd, buf, (size_t)n) < 0) return;
			}
		}
	}
}

static enum errorcode check_credentials(unsigned char* buf, size_t n) {
	if(n < 5) return EC_GENERAL_FAILURE;
	if(buf[0] != 1) return EC_GENERAL_FAILURE;
	unsigned ulen, plen;
	ulen=buf[1];
	if(n < 2 + ulen + 2) return EC_GENERAL_FAILURE;
	plen=buf[2+ulen];
	if(n < 2 + ulen + 1 + plen) return EC_GENERAL_FAILURE;
	char user[256], pass[256];
	memcpy(user, buf+2, ulen);
	memcpy(pass, buf+2+ulen+1, plen);
	user[ulen] = 0;
	pass[plen] = 0;
	if(!strcmp(user, auth_user) && !strcmp(pass, auth_pass)) return EC_SUCCESS;
	return EC_NOT_ALLOWED;
}

static int handshake(struct thread *t) {
	unsigned char buf[1024];
	ssize_t n;
	int ret;
	enum authmethod am;
	t->state = SS_1_CONNECTED;
	while((n = recv(t->client.fd, buf, sizeof buf, 0)) > 0) {
		switch(t->state) {
			case SS_1_CONNECTED:
				am = check_auth_method(buf, n, &t->client);
				if(am == AM_NO_AUTH) t->state = SS_3_AUTHED;
				else if (am == AM_USERNAME) t->state = SS_2_NEED_AUTH;
				send_auth_response(t->client.fd, 5, am);
				if(am == AM_INVALID) return -1;
				break;
			case SS_2_NEED_AUTH:
				ret = check_credentials(buf, n);
				send_auth_response(t->client.fd, 1, ret);
				if(ret != EC_SUCCESS)
					return -1;
				t->state = SS_3_AUTHED;
				if(auth_ips && !pthread_rwlock_wrlock(&auth_ips_lock)) {
					if(!is_in_authed_list(&t->client.addr))
						add_auth_ip(&t->client.addr);
					pthread_rwlock_unlock(&auth_ips_lock);
				}
				break;
			case SS_3_AUTHED:
				ret = connect_socks_target(buf, n, &t->client);
				if(ret < 0) {
					send_error(t->client.fd, ret*-1);
					return -1;
				}
				send_error(t->client.fd, EC_SUCCESS);
				return ret;
		}
	}
	return -1;
}

static void* clientthread(void *data) {
	struct thread *t = data;
	struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
	setsockopt(t->client.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(t->client.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	int remotefd = handshake(t);
	if(remotefd != -1) {
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		setsockopt(t->client.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(t->client.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		copyloop(t->client.fd, remotefd);
		close(remotefd);
	}
	close(t->client.fd);
	atomic_store(&t->done, 1);
	return 0;
}

/* allocate a struct thread, preferring the recycle pool over malloc
	  to cut down allocator churn under high connection rates. */
static struct thread* thread_alloc(void) {
	size_t sz = sblist_getsize(threadpool);
	if(sz) {
		struct thread* t = *((struct thread**)sblist_get(threadpool, sz - 1));
		sblist_delete_fast(threadpool, sz - 1);
		return t;
	}
	return malloc(sizeof (struct thread));
}

/* return a thread struct to the recycle pool. only called from the main
	  accept loop, so the pool needs no locking. on OOM the struct is simply
	  freed since we were going to free it anyway before adding the freelist. */
static void thread_release(struct thread *t) {
	if(!sblist_add(threadpool, &t))
		free(t);
}

static void collect(sblist *threads) {
	size_t i;
	for(i=0;i<sblist_getsize(threads);) {
		struct thread* thread = *((struct thread**)sblist_get(threads, i));
		if(atomic_load(&thread->done)) {
			pthread_join(thread->pt, 0);
			sblist_delete_fast(threads, i);
			thread_release(thread);
		} else
			i++;
	}
}

static int usage(void) {
	dprintf(2,
		"MicroSocks SOCKS5 Server\n"
		"------------------------\n"
		"usage: microsocks -1 -q -i listenip -p port -u user -P pass -b bindaddr -w ips\n"
		"all arguments are optional.\n"
		"by default listenip is 0.0.0.0 and port 1080.\n\n"
		"option -q disables logging.\n"
		"option -b specifies which ip outgoing connections are bound to\n"
		"option -w allows to specify a comma-separated whitelist of ip addresses,\n"
		" that may use the proxy without user/pass authentication.\n"
		" e.g. -w 127.0.0.1,192.168.1.1.1,::1 or just -w 10.0.0.1\n"
		" to allow access ONLY to those ips, choose an impossible to guess user/pw combo.\n"
		"option -1 activates auth_once mode: once a specific ip address\n"
		" authed successfully with user/pass, it is added to a whitelist\n"
		" and may use the proxy without auth.\n"
		" this is handy for programs like firefox that don't support\n"
		" user/pass auth. for it to work you'd basically make one connection\n"
		" with another program that supports it, and then you can use firefox too.\n"
	);
	return 1;
}

/* prevent username and password from showing up in top. */
static void zero_arg(char *s) {
	size_t i, l = strlen(s);
	for(i=0;i<l;i++) s[i] = 0;
}

int main(int argc, char** argv) {
	int ch;
	const char *listenip = "0.0.0.0";
	char *p, *q;
	unsigned port = 1080;
	while((ch = getopt(argc, argv, ":1qb:i:p:u:P:w:")) != -1) {
		switch(ch) {
			case 'w': /* fall-through */
			case '1':
				if(!auth_ips)
					auth_ips = sblist_new(sizeof(union sockaddr_union), 8);
				if(ch == '1') break;
				p = optarg;
				while(1) {
					union sockaddr_union ca;
					if((q = strchr(p, ','))) *q = 0;
					if(resolve_sa(p, 0, &ca)) {
						dprintf(2, "error: failed to resolve %s\n", p);
						return 1;
					}
					add_auth_ip(&ca);
					if(q) *(q++) = ',', p = q;
					else break;
				}
				break;
			case 'q':
				quiet = 1;
				break;
			case 'b':
				resolve_sa(optarg, 0, &bind_addr);
				break;
			case 'u':
				auth_user = strdup(optarg);
				zero_arg(optarg);
				break;
			case 'P':
				auth_pass = strdup(optarg);
				zero_arg(optarg);
				break;
			case 'i':
				listenip = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case ':':
				dprintf(2, "error: option -%c requires an operand\n", optopt);
				/* fall through */
			case '?':
				return usage();
		}
	}
	if((auth_user && !auth_pass) || (!auth_user && auth_pass)) {
		dprintf(2, "error: user and pass must be used together\n");
		return 1;
	}
	if(auth_ips && !auth_pass) {
		dprintf(2, "error: -1/-w options must be used together with user/pass\n");
		return 1;
	}
	signal(SIGPIPE, SIG_IGN);
	struct server s;
	sblist *threads = sblist_new(sizeof (struct thread*), 8);
	threadpool = sblist_new(sizeof (struct thread*), 8);
	if(server_setup(&s, listenip, port)) {
		perror("server_setup");
		return 1;
	}
	server = &s;

	while(1) {
		collect(threads);
		struct client c;
		struct thread *curr = thread_alloc();
		if(!curr) goto oom;
		atomic_init(&curr->done, 0);
		if(server_waitclient(&s, &c)) {
			dolog("failed to accept connection\n");
			thread_release(curr);
			usleep(FAILURE_TIMEOUT);
			continue;
		}
		curr->client = c;
		if(!sblist_add(threads, &curr)) {
			close(curr->client.fd);
			thread_release(curr);
			oom:
			dolog("rejecting connection due to OOM\n");
			usleep(FAILURE_TIMEOUT); /* prevent 100% CPU usage in OOM situation */
			continue;
		}
		pthread_attr_t *a = 0, attr;
		if(pthread_attr_init(&attr) == 0) {
			a = &attr;
			pthread_attr_setstacksize(a, THREAD_STACK_SIZE);
		}
		if(pthread_create(&curr->pt, a, clientthread, curr) != 0) {
			dolog("pthread_create failed. OOM?\n");
			close(curr->client.fd);
			sblist_delete_fast(threads, sblist_getsize(threads) - 1);
			thread_release(curr);
		}
		if(a) pthread_attr_destroy(&attr);
	}
}
