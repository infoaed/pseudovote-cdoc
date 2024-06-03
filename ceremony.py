#!/usr/bin/env python3

import secrets
import time, datetime

from cdoc_tools import encrypt_cdoc
from ldap_query import get_certs
from voter_card import create_pdf

import progressbar

VOTERLIST = "voterlist.txt"
URL = "https://pseudovote.net/test"

if __name__ == "__main__":
    start_time = time.time()

    print(f"Starting pseudonym ceremony at {datetime.datetime.now()}")
    print()

    with open(VOTERLIST, "r") as infile:
        voters = list(set(infile.read().split()))
    voter_count = len(voters)

    print("Eligible voters", voter_count)

    pseudonyms = set()
    while len(pseudonyms) < voter_count:
        pseudonyms.add(secrets.token_urlsafe())

    print("Shuffling pseudonyms...")

    pseudonyms = list(pseudonyms)
    shuffled_pseudonyms = []
    while(pseudonyms):
        shuffled_pseudonyms.append(pseudonyms.pop(secrets.randbelow(len(pseudonyms))))

    print("Shuffling voters...")

    processed_voters = []
    while(voters):
        processed_voters.append(voters.pop(secrets.randbelow(len(voters))))

    assert(len(processed_voters) == len(shuffled_pseudonyms))

    print("Encrypting pseudonyms...")

    bar = progressbar.ProgressBar(voter_count).start()

    cert_count = 0
    container_count = 0
    
    for pseudonym in shuffled_pseudonyms:
        voter = processed_voters.pop()
        certs = get_certs(voter)
        if len(certs) == 0:
            print(f"{voter} not CDOC capable!")
            continue
        encrypt_cdoc("hääletustunnus.pdf", create_pdf(URL, pseudonym), certs, f"con/{voter}.cdoc")
        bar.update(voter_count - len(processed_voters))
        cert_count += len(certs)
        container_count += 1

    assert(not processed_voters)

    print()
    print(f"Encrypted {container_count} containers for {cert_count} certs...")
    print(f"Shuffling {len(shuffled_pseudonyms)} pseudonyms for quarantine...")

    pseudonym_list = []
    while(shuffled_pseudonyms):
        index = secrets.randbelow(len(shuffled_pseudonyms))
        pseudonym_list.append(shuffled_pseudonyms.pop(index))

    end_time = time.time()
    tstr = time.strftime("%H:%M:%S", time.gmtime(end_time-start_time))

    print(f"Time since start {tstr} / {end_time-start_time}" )

    pseudonym_list = "\n".join(pseudonym_list) + "\n"
        
    encrypted = 0
    while((decryptor := input("encrypt> ")) != "end"):
        if len(decryptor) != 11 or not decryptor.isnumeric():
            continue
        if not encrypted:
            quarantine = encrypt_cdoc(f"pseudonüümid.txt", bytes(pseudonym_list, "utf-8"), get_certs(decryptor))
        else:
            quarantine = encrypt_cdoc(f"quarantine_{last_decryptor}.cdoc", quarantine, get_certs(decryptor))
        encrypted += 1
        last_decryptor = decryptor
        print(f"ENCRYPTED x{encrypted}")

    with open(f"quarantine_{last_decryptor}.cdoc", 'wb') as outfile:
        outfile.write(quarantine)

    print(f"Pseudonym ceremony ended at {datetime.datetime.now()}")
        
    print()

    print("Thanks for taking digital democracy seriously!")
