/* snmpget.c - SNMP OID retrieval functions for sdig

   Copyright (C) 2002  Russell Kroll <rkroll@exploits.org>

   based on snmp-ups.c from Network UPS Tools:

 *  Copyright (C) 2002 Arnaud Quette <arnaud.quette@free.fr>
 *  some parts are Copyright (C) :
 *                Hans Ekkehard Plesser <hans.plesser@itf.nlh.no>

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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "common.h"

	netsnmp_pdu *response;

static int snmpget(char *host, char *community, char *reqoid)
{
	int	status;
	netsnmp_session session, *ss;
	netsnmp_pdu *pdu;

	oid	name[MAX_OID_LEN];
	size_t	name_length = MAX_OID_LEN;

	debug(5, "snmpget: [%s] [%s] [%s]\n", host, community, reqoid);

	snmp_sess_init(&session);

	session.version = SNMP_VERSION_1;
	session.peername = host;
	session.community = community;
	session.community_len = strlen(community);

	init_snmp("sdig");

	SOCK_STARTUP;

	ss = snmp_open(&session);

	if (!ss) {
		snmp_sess_perror("startup", &session);
		snmp_log(LOG_ERR, "sdig: startup failed");
		SOCK_CLEANUP;
		exit(1);
	}

	pdu = snmp_pdu_create(SNMP_MSG_GET);

	if (!snmp_parse_oid(reqoid, name, &name_length)) {
		snmp_perror(reqoid);
		SOCK_CLEANUP;
		exit(1);
	}

	snmp_add_null_var(pdu, name, name_length);

	status = snmp_synch_response(ss, pdu, &response);

	snmp_close(ss);
	SOCK_CLEANUP;

	if ((status == STAT_SUCCESS) && (response->errstat == SNMP_ERR_NOERROR))
		return 1;

	return 0;
}

int snmpget_int(char *host, char *community, char *reqoid)
{
	int	ret;
	long	final;

	ret = snmpget(host, community, reqoid);

	if (ret != 1)
		return -1;

	if (response->variables->type != ASN_INTEGER) {
		fprintf(stderr, "snmpget: wanted integer, got type %d\n",
			response->variables->type);
		return -1;
	}

	final = *response->variables->val.integer;
	snmp_free_pdu(response);

	return final;
}

char *snmpget_mac(char *host, char *community, char *reqoid)
{
	int	ret, i;
	static	char	final[7];

	ret = snmpget(host, community, reqoid);

	if (ret != 1)
		return NULL;

	if (response->variables->type != ASN_OCTET_STR) {
		fprintf(stderr, "snmpget: wanted octet string, got type %d\n",
			response->variables->type);
		return NULL;
	}

	if (response->variables->val_len != 6) {
		fprintf(stderr, "snmpget: invalid length %d\n",
			response->variables->val_len);
		return NULL;
	}

	for (i = 0; i < 6; i++)
		final[i] = response->variables->val.string[i];

	snmp_free_pdu(response);
	return final;
}

char *snmpget_str(char *host, char *community, char *reqoid)
{
	int	ret;
	char	*final;

	ret = snmpget(host, community, reqoid);

	if (ret != 1)
		return NULL;

	if (response->variables->type != ASN_OCTET_STR) {
		fprintf(stderr, "snmpget: wanted octet string, got type %d\n",
			response->variables->type);
		return NULL;
	}

	if (response->variables->val_len == 0)
	    	return NULL;

	final = malloc(response->variables->val_len + 1);
	snprintf(final, response->variables->val_len + 1, "%s", 
		response->variables->val.string);

	snmp_free_pdu(response);
	return final;
}
