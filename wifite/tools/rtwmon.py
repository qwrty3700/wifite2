#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import subprocess
import fcntl
from typing import List, Optional

from .dependency import Dependency
from ..util.process import Process
from ..util.color import Color
from ..config import Configuration
from ..model.target import Target
from ..model.client import Client

class RtwmonIface:
    def __init__(self, driver, vid, pid, bus, addr):
        self.driver = driver
        self.vid = vid
        self.pid = pid
        self.bus = bus
        self.addr = addr
        # Construct a unique pseudo-interface name
        self.interface = f"rtwmon-{bus}-{addr}"
        self.phy = "usb"
        self.chipset = f"Realtek {driver}"

    def __str__(self):
        return f"{self.interface} ({self.driver})"

class Rtwmon(Dependency):
    dependency_required = False
    dependency_name = 'rtwmon'
    dependency_url = 'https://github.com/kimocoder/rtwmon' # Placeholder

    RTWMON_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'rtwmon', 'rtwmon.py'))

    @staticmethod
    def get_interfaces() -> List[RtwmonIface]:
        """
        Detects compatible USB devices using rtwmon.py list command.
        """
        interfaces = []
        if not os.path.exists(Rtwmon.RTWMON_PATH):
            return []

        try:
            # Call rtwmon.py list
            # We need to run it with python3
            cmd = ['python3', Rtwmon.RTWMON_PATH, 'list']
            proc = Process(cmd)
            output = proc.stdout()
            
            for line in output.split('\n'):
                line = line.strip()
                if not line: continue
                # Expected format: driver:VID:PID:BUS:ADDR
                parts = line.split(':')
                if len(parts) >= 5:
                    driver = parts[0]
                    vid = parts[1]
                    pid = parts[2]
                    bus = parts[3]
                    addr = parts[4]
                    interfaces.append(RtwmonIface(driver, vid, pid, bus, addr))
        except Exception as e:
            Color.pl(f"{{R}}Error detecting rtwmon devices: {e}{{W}}")
        
        return interfaces

    @staticmethod
    def is_rtwmon_interface(interface_name: str) -> bool:
        return interface_name.startswith('rtwmon-')

    @staticmethod
    def get_device_info(interface_name: str):
        """
        Parses the pseudo-interface name to get bus and address.
        """
        if not Rtwmon.is_rtwmon_interface(interface_name):
            return None
        # rtwmon-BUS-ADDR
        try:
            parts = interface_name.split('-')
            return {'bus': parts[1], 'address': parts[2]}
        except:
            return None


class RtwmonAirodump(Dependency):
    dependency_required = True
    dependency_name = 'rtwmon'
    dependency_url = 'https://github.com/kimocoder/rtwmon'
    _ssid_cache = {}
    _channel_cache = {}

    def __init__(self, interface=None, channel=None, encryption=None,
                 wps=None, target_bssid=None,
                 output_file_prefix='rtwmon_scan',
                 ivs_only=False, skip_wps=False, delete_existing_files=True):
        if interface is None:
            interface = Configuration.interface
        self.interface = interface
        self.channel = channel
        self.target_bssid = target_bssid
        self.encryption = encryption
        self.output_file_prefix = output_file_prefix
        self.output_file = Configuration.temp(f"rtwmon_{interface}.scan")
        self.error_file = Configuration.temp(f"rtwmon_{interface}.error")
        self.pid = None
        self.stdout_file = None
        self.stderr_file = None
        self.decloaking = False
        self.targets = []
        self.targets_dict = {}
        self.clients_pending = {}
        self._attack_clients = {}
        self._stderr_pos = 0
        self._station_scan_bssid = None

    def find_files(self, endswith=None):
        result = []
        temp = Configuration.temp()
        try:
            for fil in os.listdir(temp):
                if not fil.startswith(self.output_file_prefix):
                    continue
                if endswith is None or fil.endswith(endswith):
                    result.append(os.path.join(temp, fil))
        except FileNotFoundError:
            pass

        for fil in (self.output_file, self.error_file):
            if os.path.exists(fil) and (endswith is None or fil.endswith(endswith)):
                if fil not in result:
                    result.append(fil)
        return result

    def __enter__(self):
        # Clean old file
        if os.path.exists(self.output_file):
            try:
                os.remove(self.output_file)
            except OSError:
                pass
        if os.path.exists(self.error_file):
            try:
                os.remove(self.error_file)
            except OSError:
                pass

        # Build command
        info = Rtwmon.get_device_info(self.interface)
        if not info:
             raise Exception(f"Invalid rtwmon interface: {self.interface}")

        if self.target_bssid:
            # Attack mode: use deauth-burst
            pcap_file = Configuration.temp(f"{self.output_file_prefix}.cap")
            # Clean old pcap
            if os.path.exists(pcap_file):
                try: os.remove(pcap_file)
                except: pass

            try:
                burst_interval_ms = int(float(getattr(Configuration, 'wpa_deauth_timeout', 2) or 2) * 1000)
            except Exception:
                burst_interval_ms = 2000
            if burst_interval_ms < 200:
                burst_interval_ms = 200

            try:
                burst_size = int(getattr(Configuration, 'num_deauths', 10) or 10)
            except Exception:
                burst_size = 10
            if burst_size < 1:
                burst_size = 1
            
            cmd = [
                'python3', '-u', Rtwmon.RTWMON_PATH,
                '--bus', info['bus'],
                '--address', info['address'],
                'deauth-burst',
                '--channel', str(self.channel or 1),
                '--bssid', self.target_bssid,
                '--target-mac', 'ff:ff:ff:ff:ff:ff',
                '--pcap', pcap_file,
                '--burst-size', str(burst_size),
                '--burst-interval-ms', str(burst_interval_ms),
            ]
        else:
            # Scan mode
            cmd = [
                'python3', '-u', Rtwmon.RTWMON_PATH,
                '--bus', info['bus'],
                '--address', info['address'],
                'scan',
            ]
            
            if self.channel:
                cmd.extend(['--channels', str(self.channel)])
            else:
                cmd.extend(['--channels', '1-13']) # Default
        
        # Start process, redirect stderr to file, stdout to PIPE
        self.stderr_file = open(self.error_file, 'w')
        # We use subprocess.PIPE explicitly, although Process wrapper defaults to it if stdout=None
        self.pid = Process(cmd, stdout=subprocess.PIPE, stderr=self.stderr_file)
        
        # Set non-blocking on stdout pipe
        try:
            fd = self.pid.pid.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        except Exception:
            pass
            
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.pid:
            self.pid.interrupt()
        if self.stdout_file:
            self.stdout_file.close()
        if self.stderr_file:
            self.stderr_file.close()
        
        # Check for errors if process exited
        if os.path.exists(self.error_file) and os.path.getsize(self.error_file) > 0:
             with open(self.error_file, 'r') as f:
                 err_content = f.read().strip()
                 if err_content:
                     if "KeyboardInterrupt" not in err_content or "Traceback" not in err_content:
                         Color.pl(f"{{R}}rtwmon error: {{O}}{err_content}{{W}}")

        if os.path.exists(self.output_file):
            try:
                os.remove(self.output_file)
            except OSError:
                pass

    def get_targets(self, old_targets=None, apply_filter=True, target_archives=None):
        if self.target_bssid:
            essid = RtwmonAirodump._ssid_cache.get(self.target_bssid.lower(), '')
            bssid_key = self.target_bssid.lower()
            # In attack mode, return the target we are attacking
            fields = [''] * 15
            fields[0] = self.target_bssid
            fields[3] = str(self.channel)
            fields[5] = self.encryption or 'WPA2'
            fields[7] = 'PSK'
            fields[8] = '-50'
            fields[9] = '100' # Fake beacons to keep it alive
            fields[10] = '0'
            fields[11] = '0.0.0.0'
            fields[12] = str(len(essid))
            fields[13] = essid
            
            target = Target(fields)
            seen_set = self._attack_clients.get(bssid_key)
            if seen_set:
                for sta in sorted(seen_set):
                    client_fields = [''] * 7
                    client_fields[0] = sta
                    client_fields[3] = '-50'
                    client_fields[4] = '1'
                    client_fields[5] = self.target_bssid
                    try:
                        client = Client(client_fields)
                    except Exception:
                        continue
                    target.clients.append(client)

            def _remember_client(sta_mac: str):
                if not sta_mac:
                    return
                s = self._attack_clients.get(bssid_key)
                if s is None:
                    s = set()
                    self._attack_clients[bssid_key] = s
                sta_norm = sta_mac.lower()
                if sta_norm in s:
                    return
                s.add(sta_norm)
                client_fields = [''] * 7
                client_fields[0] = sta_norm
                client_fields[3] = '-50'
                client_fields[4] = '1'
                client_fields[5] = self.target_bssid
                try:
                    client = Client(client_fields)
                except Exception:
                    return
                if all(c.station.lower() != client.station.lower() for c in target.clients):
                    target.clients.append(client)

            try:
                if self.pid and self.pid.pid and self.pid.pid.stdout:
                    while True:
                        line_bytes = self.pid.pid.stdout.readline()
                        if not line_bytes:
                            break
                        try:
                            line = line_bytes.decode('utf-8', errors='replace').strip()
                        except Exception:
                            continue
                        if not line:
                            continue
                        if 'sta=' not in line or 'bssid=' not in line:
                            continue
                        parts = line.split()
                        kv = {}
                        for p in parts:
                            if '=' not in p:
                                continue
                            k, v = p.split('=', 1)
                            kv[k.strip().lower()] = v.strip()
                        b = kv.get('bssid', '').lower()
                        sta = (kv.get('sta') or kv.get('station') or kv.get('client') or '').lower()
                        if b == bssid_key and sta:
                            _remember_client(sta)
            except Exception:
                pass

            try:
                if os.path.exists(self.error_file):
                    with open(self.error_file, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(self._stderr_pos)
                        chunk = f.read()
                        self._stderr_pos = f.tell()
                    for line in chunk.splitlines():
                        b_m = re.search(r'\bbssid=([0-9A-Fa-f:]{17})\b', line)
                        if not b_m or b_m.group(1).lower() != self.target_bssid.lower():
                            continue
                        sta_m = re.search(r'\bsta=([0-9A-Fa-f:]{17})\b', line)
                        if not sta_m:
                            continue
                        _remember_client(sta_m.group(1))
                        client_fields = [''] * 7
                        client_fields[0] = sta_m.group(1)
                        client_fields[3] = '-50'
                        client_fields[4] = '1'
                        client_fields[5] = self.target_bssid
                        try:
                            client = Client(client_fields)
                        except Exception:
                            continue
                        if all(c.station.lower() != client.station.lower() for c in target.clients):
                            target.clients.append(client)
            except Exception:
                pass
            return [target]

        def parse_kv(line_str):
            ssid_val = None
            if ' ssid=' in line_str:
                ssid_val = line_str.split(' ssid=', 1)[1]
                line_str = line_str.split(' ssid=', 1)[0]
            parts = line_str.split()
            kv = {}
            for p in parts:
                if '=' not in p:
                    continue
                k, v = p.split('=', 1)
                kv[k.strip().lower()] = v.strip()
            if ssid_val is not None:
                kv['ssid'] = ssid_val
            return kv

        def add_client(station_mac, bssid, power='-50', packets='0'):
            client_fields = [''] * 7
            client_fields[0] = station_mac
            client_fields[3] = str(power)
            client_fields[4] = str(packets)
            client_fields[5] = bssid
            try:
                client = Client(client_fields)
            except Exception:
                return

            if bssid in self.targets_dict:
                target = self.targets_dict[bssid]
                if all(c.station.lower() != client.station.lower() for c in target.clients):
                    target.clients.append(client)
            else:
                self.clients_pending.setdefault(bssid, [])
                if all(c.station.lower() != client.station.lower() for c in self.clients_pending[bssid]):
                    self.clients_pending[bssid].append(client)

        try:
            if os.path.exists(self.error_file):
                with open(self.error_file, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(self._stderr_pos)
                    chunk = f.read()
                    self._stderr_pos = f.tell()
                for line in chunk.splitlines():
                    m = re.search(r'\bbssid=([0-9A-Fa-f:]{17})\b', line)
                    if not m:
                        continue
                    bssid = m.group(1)
                    sta_m = re.search(r'\bsta=([0-9A-Fa-f:]{17})\b', line)
                    if not sta_m:
                        continue
                    add_client(sta_m.group(1), bssid, power='-50', packets='1')
        except Exception:
            pass

        # Read from pipe non-blocking
        try:
            while True:
                if not self.pid or not self.pid.pid or not self.pid.pid.stdout:
                    break
                    
                line_bytes = self.pid.pid.stdout.readline()
                if not line_bytes: break
                
                try:
                    line = line_bytes.decode('utf-8', errors='replace').strip()
                except:
                    continue
                    
                if not line: continue
                if line.startswith('Scanning stations for '):
                    m = re.search(r'\bBSSID=([0-9A-Fa-f:]{17})\b', line)
                    if m:
                        self._station_scan_bssid = m.group(1)
                    continue
                if 'Station:' in line:
                    m = re.search(r'\bStation:\s*([0-9A-Fa-f:]{17})\b', line)
                    if m and self._station_scan_bssid:
                        seen_m = re.search(r'\bseen=([0-9]+)\b', line)
                        add_client(m.group(1), self._station_scan_bssid, power='-50', packets=(seen_m.group(1) if seen_m else '1'))
                    continue
                kv = parse_kv(line)
                station = kv.get('sta') or kv.get('station') or kv.get('client')
                if station:
                    bssid = kv.get('bssid') or '(not associated)'
                    power = kv.get('pwr') or kv.get('power') or '-50'
                    pkts = kv.get('pkts') or kv.get('packets') or kv.get('seen') or '0'
                    add_client(station, bssid, power=power, packets=pkts)
                    continue
                if 'bssid=' not in line or 'enc=' not in line or 'ssid=' not in line:
                    continue

                bssid = kv.get('bssid')
                enc = kv.get('enc')
                ssid = kv.get('ssid')
                ch = kv.get('ch') or kv.get('ds') or kv.get('tuned')
                seen = kv.get('seen') or '0'
                if not (bssid and enc and ssid is not None and ch):
                    continue

                if ssid == '<hidden>':
                    ssid = ''
                else:
                    RtwmonAirodump._ssid_cache[str(bssid).lower()] = ssid
                try:
                    RtwmonAirodump._channel_cache[str(bssid).lower()] = int(str(ch))
                except Exception:
                    pass

                fields = [''] * 15
                fields[0] = bssid
                fields[3] = ch
                enc_norm = enc
                if enc_norm == 'OPEN':
                    enc_norm = 'Open'
                fields[5] = enc_norm
                if enc_norm in ('WPA', 'WPA2'):
                    fields[6] = 'CCMP'
                    fields[7] = 'PSK'
                elif enc_norm == 'WPA3':
                    fields[6] = 'CCMP'
                    fields[7] = 'SAE'
                fields[8] = '-50'
                fields[9] = seen
                fields[10] = '0'
                fields[11] = '0.0.0.0'
                fields[12] = str(len(ssid))
                fields[13] = ssid

                existing = self.targets_dict.get(bssid)
                target = Target(fields)
                pending = self.clients_pending.pop(bssid, [])
                if pending:
                    for client in pending:
                        if all(c.station.lower() != client.station.lower() for c in target.clients):
                            target.clients.append(client)
                if existing:
                    for client in getattr(existing, 'clients', []) or []:
                        if all(c.station.lower() != client.station.lower() for c in target.clients):
                            target.clients.append(client)
                    target.wps = getattr(existing, 'wps', target.wps)
                    target.attacked = getattr(existing, 'attacked', target.attacked)
                    target.decloaked = getattr(existing, 'decloaked', target.decloaked)
                    try:
                        target.max_power = max(int(getattr(existing, 'max_power', target.max_power)), int(target.max_power))
                    except Exception:
                        pass
                self.targets_dict[bssid] = target
                
        except (IOError, OSError):
            pass
            
        return list(self.targets_dict.values())

class RtwmonAireplay(Dependency):
    dependency_required = True
    dependency_name = 'rtwmon'
    dependency_url = 'https://github.com/kimocoder/rtwmon'

    def __init__(self, target, attack_type, client_mac=None, replay_file=None):
        self.target = target
        self.attack_type = attack_type
        self.pid = None 
        self.stdout = ''
        self.error = None
        self.status = None
        self.xor_percent = '0%'
        self.start()

    def start(self):
        # Deauth is handled by RtwmonAirodump (deauth-burst)
        pass

    def stop(self):
        pass

    def is_running(self):
        return True 

    def get_output(self):
        return ""
    
    @staticmethod
    def deauth(target_bssid, essid=None, client_mac=None, num_deauths=None, timeout=2, interface=None):
        interface = interface or Configuration.interface
        if not interface or not str(interface).startswith('rtwmon-'):
            return

        info = Rtwmon.get_device_info(str(interface))
        if not info:
            return

        bssid_key = str(target_bssid).lower()
        channel = RtwmonAirodump._channel_cache.get(bssid_key)
        if not channel:
            try:
                channel = int(getattr(Configuration, 'target_channel', 0) or 0)
            except Exception:
                channel = 0
        if not channel:
            channel = 1

        client_mac = client_mac or 'ff:ff:ff:ff:ff:ff'
        num_deauths = int(num_deauths or getattr(Configuration, 'num_deauths', 10) or 10)

        cmd = [
            'python3', '-u', Rtwmon.RTWMON_PATH,
            '--bus', str(info['bus']),
            '--address', str(info['address']),
            'deauth',
            '--channel', str(int(channel)),
            '--bssid', str(target_bssid),
            '--target-mac', str(client_mac),
            '--count', str(num_deauths),
            '--delay-ms', '50',
        ]
        proc = Process(cmd, devnull=True)
        while proc.poll() is None:
            if proc.running_time() >= timeout:
                proc.interrupt()
                break
