#!/usr/bin/env python3
"""A stalling core: starts, never binds the inbound port, never exits.

Exercises the core-startup timeout path (process alive, port never
ready) so the tester must time out and kill the process.
"""
import time

time.sleep(3600)
