#!/usr/bin/env dtrace -s

#pragma D option quiet

inline int AF_INET = 2;
inline int AF_INET6 = 30;

self user_addr_t sap;
self user_addr_t sasp;
self socklen_t sas;

this struct sockaddr *sa;
this uint8_t af;
this struct sockaddr_in *s4;
this struct sockaddr_in6 *s6;

this string addr;
this uint16_t port;

syscall::connect:entry,
syscall::connect_nocancel:entry
/arg1/
{
    self->sap = arg1;
    self->sas = arg2;
}

syscall::connect:return,
syscall::connect_nocancel:return
/arg0 == 0 && self->sap/
{
    this->sa = copyin(self->sap, self->sas);
    this->af = this->sa->sa_family;
    self->sap = 0;
    self->sas = 0;
}

syscall::connect:return,
syscall::connect_nocancel:return
/this->sa && this->af == AF_INET/
{
    this->s4 = (struct sockaddr_in *) this->sa;
    this->addr = inet_ntop(this->af, &this->s4->sin_addr);
    this->port = ntohs(this->s4->sin_port);
    printf("[%Y] %5u %5u | %-16s -> %39s:%-5u |\n", walltimestamp, ppid, pid, execname, this->addr, this->port);
}

syscall::connect:return,
syscall::connect_nocancel:return
/this->sa && this->af == AF_INET6/
{
    this->s6 = (struct sockaddr_in6 *) this->sa;
    this->addr = inet_ntop(this->af, &this->s6->sin6_addr);
    this->port = ntohs(this->s6->sin6_port);
    printf("[%Y] %5u %5u | %-16s -> %39s:%-5u |\n", walltimestamp, ppid, pid, execname, this->addr, this->port);
}

syscall::accept:entry,
syscall::accept_nocancel:entry
/arg1/
{
    self->sap = arg1;
    self->sasp = arg2;
}

syscall::accept:return,
syscall::accept_nocancel:return
/arg0 >= 0 && self->sap/
{
    this->sa = copyin(self->sap, *((socklen_t *) copyin(self->sasp, sizeof (socklen_t))));
    this->af = this->sa->sa_family;
    self->sap = 0;
    self->sasp = 0;
}

syscall::accept:return,
syscall::accept_nocancel:return
/this->sa && this->af == AF_INET/
{
    this->s4 = (struct sockaddr_in *) this->sa;
    this->addr = inet_ntop(this->af, &this->s4->sin_addr);
    this->port = ntohs(this->s4->sin_port);
    printf("[%Y] %5u %5u | %-16s <- %39s:%-5u |\n", walltimestamp, ppid, pid, execname, this->addr, this->port);
}

syscall::accept:return,
syscall::accept_nocancel:return
/this->sa && this->af == AF_INET6/
{
    this->s6 = (struct sockaddr_in6 *) this->sa;
    this->addr = inet_ntop(this->af, &this->s6->sin6_addr);
    this->port = ntohs(this->s6->sin6_port);
    printf("[%Y] %5u %5u | %-16s <- %39s:%-5u |\n", walltimestamp, ppid, pid, execname, this->addr, this->port);
}
