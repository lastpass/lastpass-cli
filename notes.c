/*
 * routines for classifying secure notes
 *
 * Copyright (C) 2014-2018 LastPass.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * See LICENSE.OpenSSL for more details regarding this exception.
 */
#include <string.h>
#include "notes.h"
#include "util.h"

/* Templates for shared note types */
struct note_template note_templates[] = {
	[ NOTE_TYPE_AMEX ] = {
		.name = "American Express",
		.shortname = "amex",
		.fields = { NULL }},
	[ NOTE_TYPE_BANK ] = {
		.name = "Bank Account",
		.shortname = "bank",
		.fields = { "Bank Name", "Account Type", "Routing Number", "Account Number", "SWIFT Code", "IBAN Number", "Pin", "Branch Address", "Branch Phone", NULL }},
	[ NOTE_TYPE_CREDIT ] = {
		.name = "Credit Card",
		.shortname = "credit-card",
		.fields = { "Name on Card", "Type", "Number", "Security Code", "Start Date", "Expiration Date", NULL }},
	[ NOTE_TYPE_DATABASE ] = {
		.name = "Database",
		.shortname = "database",
		.fields = { "Type", "Hostname", "Port", "Database", "Username", "Password", "SID", "Alias", NULL }},
	[ NOTE_TYPE_DRIVERS_LICENSE ] = {
		.name = "Driver's License",
		.shortname = "drivers-license",
		.fields = { "Number", "Expiration Date", "License Class", "Name", "Address", "City / Town", "State", "ZIP / Postal Code", "Country", "Date of Birth", "Sex", "Height", NULL }},
	[ NOTE_TYPE_EMAIL ] = {
		.name = "Email Account",
		.shortname = "email",
		.fields = { "Username", "Password", "Server", "Port", "Type", "SMTP Server", "SMTP Port", NULL }},
	[ NOTE_TYPE_HEALTH_INSURANCE ] = {
		.name = "Health Insurance",
		.shortname = "health-insurance",
		.fields = { "Company", "Company Phone", "Policy Type", "Policy Number", "Group ID", "Member Name", "Member ID", "Physician Name", "Physician Phone", "Physician Address", "Co-pay", NULL }},
	[ NOTE_TYPE_IM ] = {
		.name = "Instant Messenger",
		.shortname = "im",
		.fields = { "Type", "Username", "Password", "Server", "Port", NULL }},
	[ NOTE_TYPE_INSURANCE ] = {
		.name = "Insurance",
		.shortname = "insurance",
		.fields = { "Company", "Policy Type", "Policy Number", "Expiration", "Agent Name", "Agent Phone", "URL", NULL }},
	[ NOTE_TYPE_MASTERCARD ] = {
		.name = "Mastercard",
		.shortname = "mastercard",
		.fields = { NULL }},
	[ NOTE_TYPE_MEMBERSHIP ] = {
		.name = "Membership",
		.shortname = "membership",
		.fields = { "Organization", "Membership Number", "Member Name", "Start Date", "Expiration Date", "Website", "Telephone", "Password", NULL }},
	[ NOTE_TYPE_PASSPORT ] = {
		.name = "Passport",
		.shortname = "passport",
		.fields = { "Type", "Name", "Country", "Number", "Sex", "Nationality", "Date of Birth", "Issued Date", "Expiration Date", NULL }},
	[ NOTE_TYPE_SERVER ] = {
		.name = "Server",
		.shortname = "server",
		.fields = { "Hostname", "Username", "Password", NULL }},
	[ NOTE_TYPE_SSN ] = {
		.name = "Social Security",
		.shortname = "ssn",
		.fields = { "Name", "Number", NULL }},
	[ NOTE_TYPE_SOFTWARE_LICENSE ] = {
		.name = "Software License",
		.shortname = "software-license",
		.fields = { "License Key", "Licensee", "Version", "Publisher", "Support Email", "Website", "Price", "Purchase Date", "Order Number", "Number of Licenses", "Order Total", NULL }},
	[ NOTE_TYPE_SSH_KEY ] = {
		.name = "SSH Key",
		.shortname = "ssh-key",
		.fields = { "Bit Strength", "Format", "Passphrase", "Private Key", "Public Key", "Hostname", "Date", NULL }},
	[ NOTE_TYPE_VISA ] = {
		.name = "VISA",
		.shortname = "visa",
		.fields = { NULL }},
	[ NOTE_TYPE_WIFI ] = {
		.name = "Wi-Fi Password",
		.shortname = "wifi",
		.fields = { "SSID", "Password", "Connection Type", "Connection Mode", "Authentication", "Encryption", "Use 802.1X", "FIPS Mode", "Key Type", "Protected", "Key Index", NULL }},
};

const char *notes_get_name(enum note_type note_type)
{
	if (note_type <= NOTE_TYPE_NONE || note_type >= NUM_NOTE_TYPES)
		return "";

	return note_templates[note_type].name;
}

bool note_field_is_multiline(enum note_type note_type, const char *field)
{
	return note_type == NOTE_TYPE_SSH_KEY && !strcmp(field, "Private Key");
}

bool note_has_field(enum note_type note_type, const char *field)
{
	const char **p;
	if (note_type <= NOTE_TYPE_NONE || note_type >= NUM_NOTE_TYPES)
		return true;

	p = note_templates[note_type].fields;
	while (*p) {
		if (!strcmp(field, *p))
			return true;
		p++;
	}
	return false;
}

enum note_type notes_get_type_by_shortname(const char *type_str)
{
	BUILD_BUG_ON(ARRAY_SIZE(note_templates) != NUM_NOTE_TYPES);

	size_t i;
	for (i = 0; i < NUM_NOTE_TYPES; i++) {
		if (!strcasecmp(type_str, note_templates[i].shortname))
			return i;
	}
	return NOTE_TYPE_NONE;
}

enum note_type notes_get_type_by_name(const char *type_str)
{
	size_t i;
	for (i = 0; i < NUM_NOTE_TYPES; i++) {
		if (!strcasecmp(type_str, note_templates[i].name))
			return i;
	}
	return NOTE_TYPE_NONE;
}

char *note_type_usage()
{
	int i;
	char *start = "--note-type=TYPE\n\nValid values for TYPE:\n";
	size_t alloc_len = strlen(start) + 1;
	char *usage_str;

	for (i = 0; i < NUM_NOTE_TYPES; i++)
		alloc_len += strlen(note_templates[i].shortname) + 2;

	usage_str = xcalloc(1, alloc_len);
	strlcat(usage_str, start, alloc_len);
	for (i = 0; i < NUM_NOTE_TYPES; i++) {
		strlcat(usage_str, "\t", alloc_len);
		strlcat(usage_str, note_templates[i].shortname, alloc_len);
		if (i != NUM_NOTE_TYPES - 1)
			strlcat(usage_str, "\n", alloc_len);
	}
	return usage_str;
}
