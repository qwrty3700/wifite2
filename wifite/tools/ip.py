#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re

from .dependency import Dependency


class Ip(Dependency):
    dependency_required = True
    dependency_name = 'ip'
    dependency_url = 'apt install iproute2'

    @classmethod
    def up(cls, interface):
        """Put interface up"""
        if str(interface).startswith('rtwmon-'):
            return

        from ..util.process import Process

        (out, err) = Process.call(f'ip link set {interface} up')
        if len(err) > 0:
            raise Exception('Error putting interface %s up:\n%s\n%s' % (interface, out, err))

    @classmethod
    def down(cls, interface):
        """Put interface down"""
        if str(interface).startswith('rtwmon-'):
            return

        from ..util.process import Process

        (out, err) = Process.call(f'ip link set {interface} down')
        if len(err) > 0:
            raise Exception('Error putting interface %s down:\n%s\n%s' % (interface, out, err))

    @classmethod
    def get_mac(cls, interface):
        if str(interface).startswith('rtwmon-'):
            return "00:00:00:00:00:00"

        from ..util.process import Process

        (out, err) = Process.call(f'ip link show {interface}')
        if match := re.search(r'([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2}', out):
            return match[0].replace('-', ':')

        raise Exception(f'Could not find the mac address for {interface}')
