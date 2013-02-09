/* sdig.c - the Switch Digger main file

   Copyright (C) 2000  Russell Kroll <rkroll@exploits.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h> 
#include <string.h> 
#include <unistd.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <sys/socket.h>

#include "sdig.h"
#include "common.h"
#include "snmpget.h"
#include "version.h"

#include "config.h"

#define true 1
#define false 0

	stype	*firstsw = NULL;
	rtype	*firstrt = NULL;
	pdtype	*firstpd = NULL;
	litype	*firstli = NULL;

	char	*wins = NULL, *nmblookup = NULL, *mactable = NULL,
		*hostinfo = NULL;

	int	verbose = 0, fastmode = 0, csvmode = 0;

static char *findmac(const char *ip, rtype *rtr)
{
	char	query[256], *ret;
	int	ifnum;

	debug(2, "\n\nfindmac: [%s] [%s] [%s]\n", ip, rtr->ip, rtr->pw);

	/* find the router's internal interface number */

	snprintf(query, sizeof(query),
		"IP-MIB::ipAdEntIfIndex.%s", rtr->ip);

	ifnum = snmpget_int(rtr->ip, rtr->pw, query);

	if (ifnum == -1)
		return NULL;

	debug(6, "router interface number for %s is %d\n",
		rtr->ip, ifnum);

	/* now look it up in the net to media table relative to the ifnum */

	/* if digging the router itself, use a different OID */

	if (!strcmp(ip, rtr->ip))
		snprintf(query, sizeof(query), 
			"interfaces.ifTable.ifEntry.ifPhysAddress.%d",
			ifnum);
	else {
		/* hardcoded ipv4 */
		snprintf(query, sizeof(query), 
				"IP-MIB::ipNetToPhysicalPhysAddress.%d.ipv4.%s",
				ifnum, ip);

		ret = snmpget_mac(rtr->ip, rtr->pw, query);
		if (NULL == ret) {
			/* try deprecated non ipv6 aware ipNetToMediaTable */
			snprintf(query, sizeof(query), 
					"ip.ipNetToMediaTable.ipNetToMediaEntry.ipNetToMediaPhysAddress.%d.%s",
					ifnum, ip);
		} else {
			return ret;
		}
	}

	ret = snmpget_mac(rtr->ip, rtr->pw, query);

	return ret;
}

static int findport(unsigned const char *mac, stype *sw)
{
	char	query[64];

	if (sw->ip == NULL) {
		printf("No switch defined for that network\n");
		exit(1);
	}

	/* build the OID for the mapping of MAC addresses to port numbers */

	/* if the switch is a force10 switch, use other mib and pass the vlan id
	 */
	if (!strcmp("force10", sw->vendor)) {
		snprintf(query, sizeof(query), ".1.3.6.1.2.1.17.7.1.2.2.1.2.%u.%u.%u.%u.%u.%u.%u",
				sw->vlanid, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	} else {
		snprintf(query, sizeof(query), "SNMPv2-SMI::mib-2.17.4.3.1.2.%u.%u.%u.%u.%u.%u",
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}

	debug(4, "findport: snmpget_int(%s, %s, %s)\n",
		sw->ip, sw->pw, query);

	return snmpget_int(sw->ip, sw->pw, query);
}

/* ROUTER <netblock> <ip> <pw> <"desc"> */
static void addrouter(char *net, const char *ip, const char *pw, 
	const char *desc)
{
	rtype	*tmp, *last;
	char	*addr, *mask;

	mask = strchr(net, '/');

	if (!mask)
		return;

	*mask++ = '\0';
	addr = net;

	tmp = last = firstrt;

	while (tmp != NULL) {
		last = tmp;
		tmp = tmp->next;
	}

	tmp = xmalloc(sizeof(rtype));
	tmp->addr = ntohl(inet_addr(addr));
	tmp->pw = xstrdup(pw);
	tmp->ip = xstrdup(ip);
	tmp->desc = xstrdup(desc);
	tmp->next = NULL;

	if (strstr(mask, ".") == NULL) { /* must be a /nn CIDR type block */
		if (atoi(mask) != 32)
			tmp->mask = ((unsigned int) ((1 << atoi(mask)) - 1) <<
				(32 - atoi(mask)));
		else
			tmp->mask = 0xffffffff; /* avoid overflow from 2^32 */
	}
	else
		tmp->mask = ntohl(inet_addr(mask));

	if (last != NULL)
		last->next = tmp;
	else
		firstrt = tmp;
}

/* SWITCH <netblock> <ip> <community> ["<desc>"] */
static void addswitch(char *net, const char *ip, const char *pw, 
	const char *desc, const char *vendor, const char *vlanid)
{
	stype	*tmp, *last;
	char	*addr, *mask;

	mask = strchr(net, '/');

	if (!mask)
		return;

	*mask++ = '\0';
	addr = net;

	tmp = last = firstsw;

	while (tmp != NULL) {
		last = tmp;
		tmp = tmp->next;
	}

	tmp = xmalloc(sizeof(stype));
	tmp->addr = ntohl(inet_addr(addr));
	tmp->pw = xstrdup(pw);
	tmp->ip = xstrdup(ip);
	tmp->desc = xstrdup(desc);
	/* check if this is a special vendor switch */
	if (vendor) {
		tmp->vendor = xstrdup(vendor);
		tmp->vlanid = strtol(vlanid, (char **) NULL, 10);
	} else {
		tmp->vendor = "default";
		tmp->vlanid = 0;
	}
	tmp->firstlink = NULL;
	tmp->next = NULL;

	if (strstr(mask, ".") == NULL) {  /* must be a /nn CIDR type block */
		if (atoi(mask) != 32)
			tmp->mask = ((unsigned int) ((1 << atoi(mask)) - 1) <<
				(32 - atoi(mask)));
		else
			tmp->mask = 0xffffffff; /* avoid overflow from 2^32 */
	}
	else
		tmp->mask = ntohl(inet_addr(mask));

	if (last != NULL)
		last->next = tmp;
	else
		firstsw = tmp;
}

/* LINKINFO <ip> <port> "<desc>" */
static void addli(const char *ip, const char *port, const char *desc)
{
	litype	*tmp, *last;

	tmp = last = firstli;

	while (tmp) {
		last = tmp;
		tmp = tmp->next;
	}

	tmp = xmalloc(sizeof(litype));
	tmp->ip = xstrdup(ip);
	tmp->port = strtol(port, (char **) NULL, 10);
	tmp->desc = xstrdup(desc);

	if (last)
		last->next = tmp;
	else
		firstli = tmp;
}

/* PORTDESC <ip> <port> "<desc>" */
static void addpd(const char *ip, const char *port, const char *desc)
{
	pdtype	*last, *tmp;

	tmp = last = firstpd;

	while (tmp) {
		last = tmp;
		tmp = tmp->next;
	}

	tmp = xmalloc(sizeof(pdtype));
	tmp->ip = xstrdup(ip);
	tmp->port = strtol(port, (char **) NULL, 10);
	tmp->desc = xstrdup(desc);

	if (last)
		last->next = tmp;
	else
		firstpd = tmp;
}

static void loadconfig(const char *fn)
{
	FILE	*conf;
	char	cfn[256], buf[256], *arg[7];
	int	ln, i;

	if (!fn) {
		snprintf(cfn, sizeof(cfn), "%s/sdig.conf", CONFPATH);
		conf = fopen(cfn, "r");
	} else {
		conf = fopen(fn, "r");
	}

	if (!conf) {
		fprintf(stderr, "fopen %s: %s\n", cfn, strerror(errno));
		exit(1);
	}

	ln = 0;
	while (fgets(buf, sizeof(buf), conf)) {
		buf[strlen(buf) - 1] = '\0';
		ln++;

		i = parseconf("sdig.conf", ln, buf, arg, 7);

		if (i == 0)
			continue;

		if (!strcmp(arg[0], "ROUTER"))
			addrouter(arg[1], arg[2], arg[3], arg[4]);
		if (!strcmp(arg[0], "SWITCH"))
			addswitch(arg[1], arg[2], arg[3], arg[4], arg[5], arg[6]);
		if (!strcmp(arg[0], "LINKINFO"))
			addli(arg[1], arg[2], arg[3]);
		if (!strcmp(arg[0], "PORTDESC"))
			addpd(arg[1], arg[2], arg[3]);
		if (!strcmp(arg[0], "WINS"))
			wins = xstrdup(arg[1]);
		if (!strcmp(arg[0], "NMBLOOKUP"))
			nmblookup = xstrdup(arg[1]);
		if (!strcmp(arg[0], "MACTABLE"))
			mactable = xstrdup(arg[1]);
		if (!strcmp(arg[0], "HOSTINFO"))
			hostinfo = xstrdup(arg[1]);
	}

	fclose(conf);
}

static char *getlink(const char *ip, long port)
{
	litype	*tmp;

	tmp = firstli;

	while (tmp) {
		if ((!strcmp(tmp->ip, ip)) && (tmp->port == port))
			return tmp->desc;

		tmp = tmp->next;
	}

	return NULL;
}

static char *getdesc(const char *ip, long port)
{
	pdtype	*tmp;

	tmp = firstpd;

	while (tmp) {
		if ((!strcmp(tmp->ip, ip)) && (tmp->port == port))
			return tmp->desc;

		tmp = tmp->next;
	}

	return NULL;
}

static const char *macmfr(unsigned char *inmac)
{
	FILE	*macdb;
	char	buf[256], *tmp, macfind[16];
	int	i;

	macdb = fopen(mactable, "r");
	if (!macdb)
		return "MAC table file not available";

	/* rewrite the MAC address into something that'll match the table */

	snprintf(macfind, sizeof(macfind), "%02x%02x%02x", 
		inmac[0], inmac[1], inmac[2]);

	while (fgets(buf, sizeof(buf), macdb)) {
		buf[strlen(buf) - 1] = '\0';

		if (!strncasecmp(buf, macfind, 6)) {
			tmp = xstrdup(&buf[7]);
			for (i = strlen(tmp) - 1; i >= 0; i--) {
				if (!isspace(tmp[i])) {
					tmp[i+1] = '\0';
					return tmp;
				}
			}
			return tmp;
		}
	}

	fclose(macdb);
	return "Not available";
}

static void help(const char *prog)
{
	printf("SNMP-based router and switch probe for locating client systems.\n\n");
	printf("usage: %s [-d] [-f <config>] [-m <MAC>] [-v] [-F] [-l <list>] [-C] (<IP> | <hostname>)\n", prog);
	printf("\n");
	printf("  -d		- increase debug level\n");
	printf("  -F		- fast mode - no DNS/NetBIOS reverse lookups\n");	
	printf("  -f <config>	- use alternate config <config>\n");
	printf("                  default %s/sdig.conf\n", CONFPATH);
	printf("  -m <MAC>	- force MAC <MAC>, xx:xx:xx:xx:xx:xx format\n");
	printf("  -v		- be verbose\n");
	printf("  -l <list>	- read a list of hosts to lookup\n");
	printf("  -C		- output in CSV format\n");
	printf("  <IP>		- IP address to find\n");
	printf("  <hostname>	- DNS/WINS hostname to find\n");

	exit(0);
}

static char *wins_resolve(const char *host)
{
	char	exec[256], buf[256];
	FILE	*wq;

	if (!wins) {
		fprintf(stderr, "WINS not defined in config file!\n");
		return NULL;
	}

	if (!nmblookup) {
		fprintf(stderr, "NMBLOOKUP not defined in config file!\n");
		return NULL;
	}

	snprintf(exec, sizeof(exec), "%s -U %s -R %s | tail -1 | cut -f 1 -d \" \"",
		nmblookup, wins, host);

	debug(5, "popen: %s\n", exec);
	wq = popen(exec, "r");

	fgets(buf, sizeof(buf), wq);
	pclose(wq);

	buf[strlen(buf) - 1] = '\0';
	debug(7, "read [%s]\n", buf);
	if (!strcmp(buf, "name_query")) {
		fprintf(stderr, "WINS lookup failed\n");
		exit(1);
	}

	printf("  Address: %s (WINS)\n", buf);

	return(xstrdup(buf));
}

static char *dns_resolve(const char *host)
{
	struct	hostent	*dns;
	struct	in_addr	addr;

	if ((dns = gethostbyname(host)) == (struct hostent *) NULL)
		return NULL;

	memcpy(&addr, dns->h_addr, dns->h_length);

	if (csvmode)
	    printf("%s;", inet_ntoa(addr));
	else
	    printf("  Address: %s (DNS)\n", inet_ntoa(addr));

	return(xstrdup(inet_ntoa(addr)));
}

static void do_ifdescr(stype *sw, long port)
{
	char	query[256], *ifdescr, *ifname;
	long	ifnum;

	/* first get the switch's ifnum for the port */
	
	snprintf(query, sizeof(query), "SNMPv2-SMI::mib-2.17.1.4.1.2.%ld", port);
	ifnum = snmpget_int(sw->ip, sw->pw, query);

	if (ifnum == -1)
		return;

	snprintf(query, sizeof(query), "IF-MIB::ifName.%ld",
		ifnum);

	ifname = snmpget_str(sw->ip, sw->pw, query);

	if (!ifname) {
		snprintf(query, sizeof(query), "IF-MIB::ifAlias.%ld", ifnum);
		snmpget_str(sw->ip, sw->pw, query);
	}

	snprintf(query, sizeof(query), "IF-MIB::ifDescr.%ld",
		ifnum);

	ifdescr = snmpget_str(sw->ip, sw->pw, query);

	if (ifname) {
	    	if (csvmode)
		    printf("%s;", ifname);
		else
		    printf(" (%s)", ifname);
		free(ifname);
	}

	if (ifdescr) {
	    	if (csvmode)
		    printf("%s;", ifdescr);
		else
		    printf(" [%s]", ifdescr);
		free(ifdescr);
	}
}

static void printport(stype *sw, long port)
{
	char	*ds, *li, *swdesc;
	char	query[256];

	/* don't print if it's a switch-switch link unless in verbose mode */

	li = getlink(sw->ip, port);

	if ((li) && (!verbose))
		return;

	snprintf(query, sizeof(query), "SNMPv2-MIB::sysName.0");
	swdesc = snmpget_str(sw->ip, sw->pw, query);

	if (csvmode) {
	    printf("%s (%s);%s;", sw->desc, swdesc, sw->ip);
	    do_ifdescr(sw, port);
	} else {
	    if (swdesc) 
		    printf("   Switch: %s (%s) - %s\n",
			    sw->desc, swdesc, sw->ip);
	    else
		    printf("   Switch: %s - %s\n", sw->desc, sw->ip);

	    printf("     Port: %ld", port);
	    do_ifdescr(sw, port);
	    printf("\n");
	    
	    if (li)
		    printf("     Link: %s\n", li);

	    ds = getdesc(sw->ip, port);
	    if (ds)
		    printf("     Info: %s\n", ds);

	    printf("\n");
	}
}

static int isip(const char *buf)
{
	int	i;

	for (i = 0; i < strlen(buf); i++)
		if ((!isdigit(buf[i])) && (buf[i] != '.'))
			return 0;

	return 1;
}

static void dnsreverse(const char *ip)
{
	struct	hostent	*dns;
	struct	in_addr	addr;

#if HAVE_INET_ATON
	inet_aton(ip, &addr);
#elif HAVE_INET_PTON
	inet_pton(AF_INET, ip, &addr);
#else
#error	Cannot convert address
#endif

	dns = gethostbyaddr((char *)&addr, sizeof(struct in_addr), AF_INET);

	if (dns) {
	    	if (csvmode)
		    printf("%s;", dns->h_name);
		else
		    printf(" Hostname: %s (DNS)\n", dns->h_name);
	}
}

static stype *find_switch(const char *ipaddr, stype *last)
{
	stype	*tmp;
	int	addrchk, swchk;

	if (last)
		tmp = last->next;
	else
		tmp = firstsw;

	while (tmp) {
		addrchk = ntohl(inet_addr(ipaddr)) & tmp->mask;
		swchk = tmp->addr & tmp->mask;

		if (swchk == addrchk)
			return tmp;

		tmp = tmp->next;
	}

	return NULL;
}

static void sprintmac(char *buf, unsigned const char *mac) {
	int	i;

	for (i = 0; i < 5; i++)
		snprintf(buf + ( i * 3), sizeof(buf), "%02x:", mac[i]);

	snprintf(buf + ( 5 * 3) , sizeof(buf), "%02x", mac[5]);
}

/* make the octet string into something nicer for humans */
static void printmac(unsigned const char *mac)
{
	char buf[256];

	sprintmac(buf, mac);
	printf("%s", buf);
}

/* ask the switch about where the MAC address is */
static void switchscan(const char *ipaddr, unsigned const char *macaddr)
{
	stype	*sw;
	long	port;

	if (!csvmode)
	    printf("\n");

	if (debuglevel >= 2) {
		printf("switchscan: seeking (%s, ", ipaddr);
		printmac(macaddr);
		printf(")\n");
	}

	sw = find_switch(ipaddr, NULL);

	while (sw) {
		debug(3, "switchscan: matched %s\n", sw->ip);

		port = findport(macaddr, sw);

		debug(3, "findport got port %d\n", port);

		if (port != -1)
			printport(sw, port);

		sw = find_switch(ipaddr, sw);
	}

	//XXX exit(0);
}

static rtype *find_router(const char *ipaddr, rtype *last)
{
	rtype	*tmp;
	int	addrchk, rtchk;

	if (last)
		tmp = last->next;
	else
		tmp = firstrt;

	while (tmp) {
		addrchk = ntohl(inet_addr(ipaddr)) & tmp->mask;
		rtchk = tmp->addr & tmp->mask;

		if (rtchk == addrchk)
			return tmp;

		tmp = tmp->next;
	}

	return NULL;
}

/* run the user's script for extra details about a host */
static void do_hostinfo(const char *ipaddr)
{
	char	exec[256];

	fflush(stdout);

	snprintf(exec, sizeof(exec), "%s %s", hostinfo, ipaddr);
	system(exec);
}

/* walk the list of routers checking for the IP address */
static int routerscan(const char *ipaddr)
{
	unsigned char	*macaddr;
	rtype	*rtr;

	/* spew out some additional info about the IP address */
	if (fastmode == 0) {
		dnsreverse(ipaddr);

		if (hostinfo)
			do_hostinfo(ipaddr);
	}

	if (!csvmode)
	    printf("\n");

	debug(2, "routerscan: looking for a router for host %s\n", ipaddr);

	/* XXX: ping code for waking up sleeping/inactive hosts */

	/* find the first one that covers this network */
	rtr = find_router(ipaddr, NULL);

	while (rtr) {
		debug(3, "routerscan: matched %s\n", rtr->ip);

		/* try to find the target IP address on this router */
		macaddr = (unsigned char*)findmac(ipaddr, rtr);

		if (macaddr) {
		    	if (csvmode) {
			    char buf[64];
			    sprintmac(buf, macaddr);
			    printf("%s;%s;%s;", rtr->desc, rtr->ip, buf);
			} else {
			    printf("   Router: %s - %s\n", rtr->desc, rtr->ip);

			    printf("      MAC: ");
			    printmac(macaddr);
			    printf(" (%s)\n", macmfr(macaddr));
			}

			switchscan(ipaddr, macaddr);
			return true;
		}

		rtr = find_router(ipaddr, rtr);
	}

	return false;

	/* XXX
	fprintf(stderr, "Error: no routers found for %s\n", ipaddr);
	exit(1);
	*/
}	

/* turn <name> into an IP address and pass it to the router scanner */
static void resolvename(const char *name)
{
	char	*ipaddr;

	/* first try DNS */
	ipaddr = dns_resolve(name);

	if (ipaddr) {
		if (routerscan(ipaddr))
		    	return;
		else {
		    	if (csvmode) {
			    printf("unknown host"); 
			    return;
			}
		}
	}
		    	

	/* now try WINS */
	ipaddr = wins_resolve(name);

	if (ipaddr)
		if (routerscan(ipaddr))
		    	return;

	fprintf(stderr, "Can't resolve %s with DNS or WINS!\n", name);
	exit(1);
}

/* see if the specified mac address is sane, and make it machine-readable */
static char *pack_mac(char *buf)
{
	int	i, cc, sl, v, mp;
	char	*ptr, *cp; 
	static	char	mac[16];

	cc = 0;
	for (i = 0; i < strlen(buf); i++) {

		if (buf[i] == ':')
			cc++;

		if ((!isxdigit(buf[i])) && (buf[i] != ':')) {
			fprintf(stderr, "Invalid MAC address specified: %s\n", buf);
			fprintf(stderr, "Valid characters are hex digits and :\n");
			exit(1);
		}
	}

	if (cc != 5) {
		fprintf(stderr, "Invalid MAC address specified: %s\n", buf);
		fprintf(stderr, "It must contain exactly 5 : separators.\n");
		exit(1);
	}

	strcpy(mac, "");
	ptr = buf;
	sl = strlen(buf);
	mp = 0;

	for (i = 0; i < sl; i++) {
		cp = strchr(ptr, ':');

		if (!cp) {
			v = strtol(ptr, (char **) NULL, 16);

			mac[mp++] = v;
			break;
		}

		*cp++ = '\0';

		v = strtol(ptr, (char **) NULL, 16);
		mac[mp++] = v;

		ptr = cp;
	}	

	return mac;
}

int main(int argc, char **argv)
{
	char	*prog, *query = NULL, *conf = NULL, *mac = NULL, *hostlist = NULL, *ptr = NULL;
	int	i, done = false;
	FILE	*hlist = NULL;
	char	buf[256];

	prog = argv[0];

	while ((i = getopt(argc, argv, "+dhf:m:vFl:C")) != EOF) {
		switch (i) {
			case 'd':
				debuglevel++;
				break;

			case 'f':
				conf = optarg;
				break;

			case 'h':
				help(prog);
				break;

			case 'm':
				mac = optarg;
				break;

			case 'v':
				verbose++;
				break;

			case 'F':
				fastmode = 1;
				break;
			case 'l':
				hostlist = optarg;
				break;
			case 'C':
			    	csvmode = true;
				break;
				
			default:
				help(prog);
		}
	}

	argc -= optind;
	argv += optind;

	if (!csvmode)
	    printf("Switch Digger Reloaded %s - http://www.shoki.org/\n\n",
		    VERSION);

	if (!hostlist && argc < 1)
		help(prog);

	if (!hostlist)
	    query = argv[0];

	loadconfig(conf);

	if (hostlist)
	    hlist = fopen(hostlist, "r");

	while (!done) {
	    if (hostlist) {
		if (!fgets(buf, sizeof(buf), hlist)) {
		    done = true;
		    break;
		}
		buf[strlen(buf) - 1] = '\0';
		ptr = buf;

		/* skip comments */
		switch (*ptr) {
		    case '#':
		    case ' ':
		    case '\n':
		    case 0:
			continue;
			break;
		}

		query = buf;
	    } else {
		done = true;
	    }

	    /* split off to resolve things based on what kind of input we got */

	    /* hostname (DNS or WINS) given */
	    if (!isip(query)) {
		    if (csvmode)
			printf("%s;", query);
		    else
			printf("    Query: %s\n", query);
		    resolvename(query);

		    /* NOTREACHED */
	    }

	    /* MAC address specified, along with target network */
	    if ((mac) && (isip(query))) {
		    printf("    Query: %s in network %s\n", 
			    mac, query);

		    switchscan(query, (unsigned char*)pack_mac(mac));

		    /* NOTREACHED */
	    }

	    /* just an IP address given */
	    if (isip(query)) {
		    printf("    Query: %s\n", query);
		    routerscan(query);

		    /* NOTREACHED */
	
	    }

	    if (csvmode) printf("\n");
	}

	if (hostlist && hlist) fclose(hlist);

	/* unknown! 
	fprintf(stderr, "Error: unknown query type!\n");
	exit(1);
	*/
	exit(0);
}
