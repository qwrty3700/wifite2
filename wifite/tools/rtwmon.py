#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import subprocess
import fcntl
import socket
import atexit
from typing import List, Optional

from .dependency import Dependency
from ..util.process import Process
from ..util.color import Color
from ..util.logger import log_debug, log_info
from ..config import Configuration
from ..model.target import Target
from ..model.client import Client

_RTWMON_RX_CONTROL_SOCKS = {}
_RTWMON_IFACE_DRIVERS = {}
_RTWMON_TERMUX_DAEMON_RESET_DONE = False


def _termux_daemon_sock() -> str:
    return "/data/data/com.termux/files/usr/tmp/rtwmon-usb.sock"


def _termux_daemon_close(sock_path: str) -> None:
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(0.2)
            s.connect(str(sock_path))
            s.sendall(b'{"method":"close"}\n')
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception:
        pass


def _termux_daemon_reset_once() -> None:
    global _RTWMON_TERMUX_DAEMON_RESET_DONE
    if _RTWMON_TERMUX_DAEMON_RESET_DONE:
        return
    _RTWMON_TERMUX_DAEMON_RESET_DONE = True
    sock_path = _termux_daemon_sock()
    _termux_daemon_close(sock_path)
    try:
        if os.path.exists(sock_path):
            os.unlink(sock_path)
    except Exception:
        pass


def _termux_daemon_close_atexit() -> None:
    try:
        _termux_daemon_close(_termux_daemon_sock())
    except Exception:
        pass


atexit.register(_termux_daemon_close_atexit)
_RTWMON_IFACE_DRIVERS = {}

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
    TERMUX_USB_RUN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'rtwmon', 'termux_usb_run.py'))

    @staticmethod
    def _is_termux() -> bool:
        if os.environ.get("TERMUX_VERSION") or os.environ.get("TERMUX_APP_PID"):
            return True
        prefix = str(os.environ.get("PREFIX", "") or "")
        if prefix.startswith("/data/data/com.termux/"):
            return True
        return os.path.exists("/data/data/com.termux/files/usr/libexec/termux-api")

    @staticmethod
    def _termux_device_path(bus: str, addr: str) -> Optional[str]:
        try:
            b = int(str(bus), 10)
            a = int(str(addr), 10)
        except Exception:
            return None
        return f"/dev/bus/usb/{b:03d}/{a:03d}"

    @staticmethod
    def _wrap_termux_usb(cmd: List[str], *, device_path: Optional[str]) -> List[str]:
        if not Rtwmon._is_termux():
            return cmd
        return cmd

    @staticmethod
    def get_interfaces() -> List[RtwmonIface]:
        """
        Detects compatible USB devices using rtwmon.py list command.
        """
        interfaces = []
        if not os.path.exists(Rtwmon.RTWMON_PATH):
            return []

        try:
            if Rtwmon._is_termux():
                _termux_daemon_reset_once()
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
                    iface = RtwmonIface(driver, vid, pid, bus, addr)
                    interfaces.append(iface)
                    try:
                        _RTWMON_IFACE_DRIVERS[str(iface.interface)] = str(driver)
                    except Exception:
                        pass
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
                 target_clients=None,
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
        self.target_clients = []
        self._burst_started_at = None
        self._burst_interval_ms = None
        self._burst_size = None
        self._burst_targets = []
        self._burst_last_logged = -1
        self._attack_pcap_file = None
        self._pcap_scan_last_time = 0.0
        self._pcap_scan_last_size = -1
        self._rx_control_sock = None
        try:
            for c in (target_clients or []):
                s = str(c).strip()
                if not s:
                    continue
                if s not in self.target_clients:
                    self.target_clients.append(s)
        except Exception:
            self.target_clients = []

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

        device_path = None
        if Rtwmon._is_termux():
            device_path = Rtwmon._termux_device_path(info.get("bus"), info.get("address"))

        bus_s = str(info.get("bus"))
        addr_s = str(info.get("address"))
        driver_s = str(_RTWMON_IFACE_DRIVERS.get(str(self.interface), "auto"))
        daemon_sock = "/data/data/com.termux/files/usr/tmp/rtwmon-usb.sock" if Rtwmon._is_termux() else ""

        if self.target_bssid:
            # Attack mode: use rx + control socket (deauth via rtwmon ctl)
            pcap_file = Configuration.temp(f"{self.output_file_prefix}.cap")
            # Clean old pcap
            if os.path.exists(pcap_file):
                try: os.remove(pcap_file)
                except: pass
            self._attack_pcap_file = pcap_file

            ctl_sock = Configuration.temp(f"rtwmon_ctl_{info.get('bus')}_{info.get('address')}.sock")
            self._rx_control_sock = str(ctl_sock)
            try:
                _RTWMON_RX_CONTROL_SOCKS[(str(info.get("bus")), str(info.get("address")))] = str(ctl_sock)
            except Exception:
                pass
            
            backend_cmd = [
                'python3', '-u', Rtwmon.RTWMON_PATH,
                '--driver', driver_s,
                '--bus', bus_s,
                '--address', addr_s,
                '--termux-daemon-sock', str(daemon_sock),
                'rx',
                '--channel', str(self.channel or 1),
                '--pcap', pcap_file,
                '--timeout-ms', '50',
                '--control-sock', str(ctl_sock),
            ]
            log_info(
                'RtwmonAirodump',
                f'rx start bssid={self.target_bssid} ch={self.channel or 1} pcap={pcap_file} control_sock={ctl_sock}',
            )
        else:
            # Scan mode
            backend_cmd = [
                'python3', '-u', Rtwmon.RTWMON_PATH,
                '--driver', driver_s,
                '--bus', bus_s,
                '--address', addr_s,
                '--termux-daemon-sock', str(daemon_sock),
                'scan',
            ]
            
            if self.channel:
                backend_cmd.extend(['--channels', str(self.channel)])
            else:
                backend_cmd.extend(['--channels', '1-13']) # Default

        cmd = Rtwmon._wrap_termux_usb(backend_cmd, device_path=device_path)
        
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

            def _remember_client(sta_mac: str, *, source: str):
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
                log_info('RtwmonAirodump', f'rx client discovered bssid={self.target_bssid} sta={sta_norm} source={source}')
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
                pcap_path = str(self._attack_pcap_file or "").strip()
                if pcap_path and Process.exists("tshark") and os.path.exists(pcap_path):
                    now = time.monotonic()
                    if (now - float(self._pcap_scan_last_time)) >= 2.0:
                        self._pcap_scan_last_time = now
                        try:
                            size = int(os.path.getsize(pcap_path))
                        except Exception:
                            size = -1
                        if size != self._pcap_scan_last_size:
                            self._pcap_scan_last_size = size

                            bssid_norm = str(self.target_bssid).lower()
                            cmd_sta_to_ap = [
                                "tshark",
                                "-r",
                                pcap_path,
                                "-n",
                                "-Y",
                                f"wlan.fc.type==2 && wlan.fc.to_ds==1 && wlan.fc.from_ds==0 && wlan.da=={bssid_norm}",
                                "-T",
                                "fields",
                                "-E",
                                "separator=,",
                                "-e",
                                "wlan.sa",
                            ]
                            out_sta_to_ap, _err1 = Process(cmd_sta_to_ap).get_output(timeout=3)

                            cmd_ap_to_sta = [
                                "tshark",
                                "-r",
                                pcap_path,
                                "-n",
                                "-Y",
                                f"wlan.fc.type==2 && wlan.fc.to_ds==0 && wlan.fc.from_ds==1 && wlan.sa=={bssid_norm}",
                                "-T",
                                "fields",
                                "-E",
                                "separator=,",
                                "-e",
                                "wlan.da",
                            ]
                            out_ap_to_sta, _err2 = Process(cmd_ap_to_sta).get_output(timeout=3)

                            mac_re = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
                            for out in (out_sta_to_ap, out_ap_to_sta):
                                for line in (out or "").splitlines():
                                    for m in [p.strip().lower() for p in line.split(",") if p.strip()]:
                                        if not mac_re.fullmatch(m):
                                            continue
                                        if m == bssid_key or m == "ff:ff:ff:ff:ff:ff":
                                            continue
                                        if (int(m.split(":")[0], 16) & 1) != 0:
                                            continue
                                        _remember_client(m, source="pcap")
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
        # Deauth is handled via rtwmon ctl socket while rx runs
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
        if num_deauths < 20:
            num_deauths = 20

        ctl_sock = None
        try:
            ctl_sock = _RTWMON_RX_CONTROL_SOCKS.get((str(info['bus']), str(info['address'])))
        except Exception:
            ctl_sock = None
        if ctl_sock:
            cmd = [
                'python3', '-u', Rtwmon.RTWMON_PATH,
                'ctl',
                '--sock', str(ctl_sock),
                'deauth',
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
            return

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
        if Rtwmon._is_termux():
            daemon_sock = str(os.environ.get("RTWMON_TERMUX_DAEMON_SOCK", "") or "").strip()
            if not daemon_sock:
                daemon_sock = "/data/data/com.termux/files/usr/tmp/rtwmon-usb.sock"
            cmd = ['python3', '-u', Rtwmon.RTWMON_PATH, '--termux-daemon-sock', daemon_sock, *cmd[3:]]
        proc = Process(cmd, devnull=True)
        while proc.poll() is None:
            if proc.running_time() >= timeout:
                proc.interrupt()
                break
