#!/usr/bin/python3
# -*- coding: utf-8 -*-
# NoSQLMap MongoDB Module

from exception import NoSQLMapException
import requests
import urllib3
import os
import sys

def args():
    return [
    ]

def netAttacks(victim, dbPort, myIP, myPort, args=None):
    # NoSQLMap MongoDB netAttacks function
    print("DB Access attacks (MongoDB)")
    # Add your MongoDB specific attacks here

