#!/usr/bin/python3
# -*- coding: utf-8 -*-
# NoSQLMap Scan Module

from exception import NoSQLMapException
import requests
import urllib3
import os
import sys

def args():
    return [
    ]

def massScan(platform):
    # NoSQLMap massScan function
    print("Scanning for anonymous " + platform + " access")
    # Add your scanning logic here

