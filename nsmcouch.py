#!/usr/bin/python3
# -*- coding: utf-8 -*-

# NoSQLMap CouchDB Module

from exception import NoSQLMapException
import requests
import urllib3
import os
import sys

def args():
    return [
    ]

def netAttacks(victim, dbPort, myIP):
    # NoSQLMap CouchDB netAttacks function
    print("DB Access attacks (CouchDB)")

