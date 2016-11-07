#!/bin/sh

kill -USR1 $(cat /foghorn/twistd.pid)
