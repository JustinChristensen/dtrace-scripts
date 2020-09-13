#!/usr/bin/env dtrace -s

#pragma D option quiet

inline int AF_INET = 2;
inline int AF_INET6 = 30;

this struct sockaddr *sa;
self struct sockaddr *sa;
this uint8_t af;
this struct sockaddr_in *s4;
this struct sockaddr_in6 *s6;
this string addr;
this uint16_t port;

syscall::connect:entry,
syscall::connect_nocancel:entry
/arg1/
{
    this->sa = copyin(arg1, sizeof (struct sockaddr));
    this->af = this->sa->sa_family;
}

syscall::connect:entry,
syscall::connect_nocancel:entry
/this->af == AF_INET/
{
    this->s4 = (struct sockaddr_in *) this->sa;
    this->addr = inet_ntop(this->af, &this->s4->sin_addr);
    this->port = ntohs(this->s4->sin_port);
    printf("[%Y] %5u %5u | %-16s  ->  %15s:%-5u |\n", walltimestamp, ppid, pid, execname, this->addr, this->port);
}

syscall::connect:entry,
syscall::connect_nocancel:entry
/this->af == AF_INET6/
{
    this->s6 = (struct sockaddr_in6 *) this->sa;
    this->addr = inet_ntop(this->af, &this->s6->sin6_addr);
    this->port = ntohs(this->s6->sin6_port);
    printf("[%Y] %5u %5u | %-16s  ->  %15s:%-5u |\n", walltimestamp, ppid, pid, execname, this->addr, this->port);
}

syscall::accept:entry,
syscall::accept_nocancel:entry
{
    self->sa = copyin(arg1, sizeof (struct sockaddr));
}

syscall::accept:return,
syscall::accept_nocancel:return
/self->sa->sa_family == AF_INET/
{
    this->s4 = (struct sockaddr_in *) self->sa;
    this->addr = inet_ntop(this->af, &this->s4->sin_addr);
    this->port = ntohs(this->s4->sin_port);
    printf("[%Y] %5u %5u | %-16s  <-  %15s:%-5u |\n", walltimestamp, ppid, pid, execname, this->addr, this->port);
    self->sa = 0;
}

syscall::accept:return,
syscall::accept_nocancel:return
/self->sa->sa_family == AF_INET6/
{
    this->s6 = (struct sockaddr_in6 *) self->sa;
    this->addr = inet_ntop(this->af, &this->s6->sin6_addr);
    this->port = ntohs(this->s6->sin6_port);
    printf("[%Y] %5u %5u | %-16s  <-  %15s:%-5u |\n", walltimestamp, ppid, pid, execname, this->addr, this->port);
    self->sa = 0;
}


