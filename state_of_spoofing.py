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
SessionMaker = None


def main():
    global q
    global SessionMaker

    args = parse_args()

    print "[*] Starting Up"
    print "[*] Initializing Database Engine at sqlite:///%(db_path)s" % {"db_path": args.db}

    engine = create_engine("sqlite:///%(db)s" % {'db': args.db})
    Base.metadata.create_all(engine)
    SessionMaker = sessionmaker(bind=engine)

    print "[*] Logging to %(logfile)s" % {"logfile": args.logfile}
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(filename=args.logfile, level=log_level)

    print "[*] Ingesting %(infile)s" % {'infile': args.domain_filename}

    try:
        with open(args.domain_filename, "r") as infile:
            for line in infile:
                q.put(line.strip())
    except IOError:
        print "Error: Could not open file"
        exit(-1)

    print "[*] Spooling up worker threads"
    for i in range(args.threads):
        t = threading.Thread(target=worker, name="Worker-%(i)s" % {"i": i}, args=(i,))
        t.daemon = True
        t.start()

    q.join()


def worker(i):
    global q

    logging.info("Spooling up worker %(i)s" % {"i": i})

    while True:
        try:
            domain = q.get()
            logging.info("[worker-%(i)s] Processing domain %(domain)s" % {"i": i, "domain": domain})
            handle_domain(domain)
            q.task_done()
        except Exception as e:
            logging.exception(e)


def handle_domain(domain):
    global SessionMaker
    session = SessionMaker()

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

    if dmarc_record is not None and spf_record is not None:
        domain_model.domain_vulnerable = not (dmarc_record.is_record_strong() and spf_record.is_record_strong())
    else:
        domain_model.domain_vulnerable = True

    session.add(domain_model)
    session.commit()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("domain_filename", help="Filename containing domains to scan")
    parser.add_argument("--db", type=str, help="Database file name", default="state.db")
    parser.add_argument("--threads", type=int, help="Number of worker threads", default=10)
    parser.add_argument("--logfile", type=str, help="Name of log file", default="state_of_spoofing.log")
    parser.add_argument("--debug", action="store_true", help="Log in debug mode", default=False)
    return parser.parse_args()


if __name__ == "__main__":
    main()
