#!/usr/bin/env python3

import ldap

LDAP_SERVER = 'ldaps://esteid.ldap.sk.ee/'
BASE_DN = 'c=EE'
OBJECT_TO_SEARCH = 'serialNumber=PNOEE-'

ENCRYPT_CAPABLE_CERTS = {"Identity card of Estonian citizen", "Identity card of European Union citizen", "Digital identity card", "Diplomatic identity card"}

connect = ldap.initialize(LDAP_SERVER)
connect.set_option(ldap.OPT_REFERRALS, 0)
connect.simple_bind_s()

def get_certs(person_code):
    res = connect.search_s(BASE_DN, ldap.SCOPE_SUBTREE, f"{OBJECT_TO_SEARCH}{person_code}")

    certs = []

    for x in res:
        name = x[0]
        parts = name.split(",")
        for p in parts:
            if p.startswith("ou="):
                ou = p[3:]
            elif p.startswith("o="):
                o = p[2:]
        
        if o in ENCRYPT_CAPABLE_CERTS and ou == "Authentication":
            certs.extend(x[1]["userCertificate;binary"])
    
    return certs
