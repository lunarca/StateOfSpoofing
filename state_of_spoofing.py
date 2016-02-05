#! /usr/bin/env python

import dnslib
import argparse
import os

from libs.subbrute import resolver

from models.domain import Domain, Base

from sqlalchemy import create_engine


def main():
    args = parse_args()

    engine = create_engine("sqlite:///%(db)s" % {'db': args.db})
    Base.metadata.create_all(engine)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("domain_filename", help="Filename containing domains to scan")
    parser.add_argument("--db", type=str, help="Database file name", default="state.db")
    return parser.parse_args()


if __name__ == "__main__":
    main()
