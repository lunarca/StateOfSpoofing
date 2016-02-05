#! /usr/bin/env python

import argparse
import Queue
import logging

import emailprotectionslib.spf as spflib
import emailprotectionslib.dmarc as dmarclib
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models.domain import Domain, Base
import threading


q = Queue.Queue()
Session = None


def main():
    global q
    global Session

    args = parse_args()

    engine = create_engine("sqlite:///%(db)s" % {'db': args.db})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    try:
        with open(args.domain_filename, "r") as infile:
            for line in infile:
                q.put(line.strip())
    except IOError:
        print "Error: Could not open file"
        exit(-1)

    for i in range(args.threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()

    q.join()


def worker():
    global q

    while True:
        try:
            domain = q.get()
            handle_domain(domain)
            q.task_done()
        except Exception as e:
            logging.exception(e)


def handle_domain(domain):
    global Session
    session = Session()

    domain_model = Domain()

    domain_model.domain = domain

    spf_record = spflib.SpfRecord.from_domain(domain)

    if spf_record is not None:
        domain_model.spf_record = spf_record.record
        domain_model.spf_strong = spf_record.is_record_strong()
    else:
        domain_model.spf_record = None
        domain_model.spf_strong = False

    dmarc_record = dmarclib.DmarcRecord.from_domain(domain)

    if dmarc_record is not None:
        domain_model.dmarc_record = dmarc_record.record
        domain_model.dmarc_policy = dmarc_record.policy
        domain_model.dmarc_strong = dmarc_record.is_record_strong()
    else:
        domain_model.dmarc_record = None
        domain_model.dmarc_policy = None
        domain_model.dmarc_strong = False

    domain_model.domain_vulnerable = not (dmarc_record.is_record_strong() and spf_record.is_record_strong())

    session.add(domain_model)
    session.commit()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("domain_filename", help="Filename containing domains to scan")
    parser.add_argument("--db", type=str, help="Database file name", default="state.db")
    parser.add_argument("--threads", type=int, help="Number of worker threads", default=10)
    return parser.parse_args()


if __name__ == "__main__":
    main()
