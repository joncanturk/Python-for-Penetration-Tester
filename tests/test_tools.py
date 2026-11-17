import argparse
import contextlib
import hashlib
import importlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import md5crack
import nmapscanner
import inforecon
import macspoofpy
import server

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=['md5crack','nmapscanner','inforecon','macspoofpy','new_mac','server','grabber','floodz','hiddenwifi']


class ToolsTests(unittest.TestCase):
    def test_imports_have_no_network_process_or_cli_side_effects(self):
        with patch('socket.socket',side_effect=AssertionError('network on import')), patch('subprocess.run',side_effect=AssertionError('process on import')), patch('argparse.ArgumentParser.parse_args',side_effect=AssertionError('parse on import')):
            for name in SCRIPTS:
                importlib.reload(importlib.import_module(name))

    def test_help_without_optional_dependencies(self):
        for name in SCRIPTS:
            with self.subTest(script=name):
                result=subprocess.run([sys.executable,str(ROOT/(name+'.py')),'--help'],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn('usage:',result.stdout)

    def test_md5_matches_empty_and_preserves_whitespace(self):
        for candidate in ['', ' spaced ', 'hello']:
            digest=hashlib.md5(candidate.encode(),usedforsecurity=False).hexdigest()
            self.assertEqual(md5crack.find_match(digest.upper(),['wrong\n',candidate+'\n']),candidate)
        self.assertIsNone(md5crack.find_match('0'*32,['wrong']))

    def test_md5_rejects_invalid_hash_and_stops_at_match(self):
        with self.assertRaises(ValueError):
            md5crack.find_match('invalid',[])
        def words():
            yield 'hello'
            raise AssertionError('read beyond match')
        self.assertEqual(md5crack.find_match('5d41402abc4b2a76b9719d911017c592',words()),'hello')

    def test_md5_legacy_cli_and_missing_file(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(md5crack.main(['-md5','5d41402abc4b2a76b9719d911017c592','-w',str(ROOT/'examples/words.txt')]),0)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            md5crack.main(['-md5','0'*32,'-w','does-not-exist.txt'])
        self.assertEqual(error.exception.code,2)

    def test_nmap_xml_preserves_down_hosts_and_aggregated_states(self):
        result=nmapscanner.parse_xml((ROOT/'examples/nmap.xml').read_text())
        self.assertEqual(result['hosts'][0]['ports'][0]['state'],'open')
        self.assertEqual(result['hosts'][0]['extraports'][0]['state'],'closed')
        self.assertEqual(result['hosts'][1]['status'],'down')
        self.assertEqual(result['hosts'][1]['ports'],[])
        self.assertEqual(nmapscanner.parse_xml('<nmaprun/>'),{'hosts':[]})

    def test_targets_reject_options_ranges_and_shell_text(self):
        for value in ['--script=all','-sV','192.0.2.0/24','host;id','https://example.com','a b','']:
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                nmapscanner.validate_target(value)
        for value in ['127.0.0.1','::1','lab.example']:
            self.assertEqual(nmapscanner.validate_target(value),value)

    def test_ports_are_validated_and_deduplicated(self):
        self.assertEqual(nmapscanner.parse_ports('443,80,80'),'80,443')
        for value in ['0','65536','1-100','abc','']:
            with self.assertRaises(argparse.ArgumentTypeError):
                nmapscanner.parse_ports(value)

    def test_nmap_single_invocation_ipv6_and_timeout(self):
        with patch('nmapscanner.subprocess.run',return_value=subprocess.CompletedProcess([],0,'<nmaprun/>','')) as run:
            self.assertEqual(nmapscanner.scan('::1','22,80',5),{'hosts':[]})
            command=run.call_args.args[0]
            self.assertIn('-6',command)
            self.assertEqual(command[-1],'::1')
            self.assertEqual(run.call_args.kwargs['timeout'],10)
            self.assertNotIn('shell',run.call_args.kwargs)
            run.assert_called_once()

    def test_scan_errors_produce_exit_two(self):
        for failure in [FileNotFoundError('nmap'),subprocess.TimeoutExpired('nmap',1)]:
            with patch('nmapscanner.subprocess.run',side_effect=failure), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                nmapscanner.main(['127.0.0.1'])
            self.assertEqual(error.exception.code,2)

    def test_header_url_validation_and_no_redirect(self):
        for value in ['ftp://example.com','https://user:secret@example.com','https://example.com/a b','example.com']:
            with self.assertRaises(ValueError):
                inforecon.validate_url(value)
        self.assertIsNone(inforecon.NoRedirect().redirect_request(None,None,302,'',{},'https://elsewhere.example'))

    def test_header_request_is_head_and_bounded(self):
        response=MagicMock()
        response.__enter__.return_value=response
        response.code=200
        response.headers.items.return_value=[('X-Test','yes')]
        with patch('inforecon.build_opener') as factory:
            factory.return_value.open.return_value=response
            result=inforecon.inspect_headers('https://example.com',7)
            args,kwargs=factory.return_value.open.call_args
            self.assertEqual(args[0].method,'HEAD')
            self.assertEqual(kwargs['timeout'],7)
            self.assertEqual(result['status'],200)
            response.__exit__.assert_called_once()

    def test_mac_is_unicast_locally_administered_and_alias_shared(self):
        import new_mac
        self.assertIs(new_mac.new_mac,macspoofpy.new_mac)
        for _ in range(50):
            value=macspoofpy.new_mac()
            self.assertEqual(len(value),17)
            self.assertEqual(int(value[:2],16)&3,2)

    def test_mac_restores_up_state_after_address_failure(self):
        calls=[]
        def run(command,**kwargs):
            calls.append(command)
            if 'address' in command:
                raise subprocess.CalledProcessError(1,command)
            return subprocess.CompletedProcess(command,0,'[{"flags":["UP"]}]','')
        with patch('macspoofpy.sys.platform','linux'), patch('macspoofpy.subprocess.run',side_effect=run), self.assertRaises(subprocess.CalledProcessError):
            macspoofpy.apply_mac('eth0','02:00:00:00:00:01')
        self.assertEqual(calls[-1][-1],'up')

    def test_mac_keeps_down_interface_down(self):
        with patch('macspoofpy.sys.platform','linux'), patch('macspoofpy.subprocess.run',return_value=subprocess.CompletedProcess([],0,'[{"flags":[]}]','')) as run:
            macspoofpy.apply_mac('eth0','02:00:00:00:00:01')
            self.assertEqual(run.call_count,2)

    def test_server_loopback_timeouts_and_sendall(self):
        with patch('server.socket.socket') as factory, contextlib.redirect_stdout(io.StringIO()):
            listener=factory.return_value.__enter__.return_value
            connection=MagicMock()
            connection.__enter__.return_value=connection
            listener.accept.return_value=(connection,('127.0.0.1',12345))
            server.serve(9337,4)
            listener.bind.assert_called_once_with(('127.0.0.1',9337))
            listener.settimeout.assert_called_once_with(4)
            connection.__enter__.return_value.sendall.assert_called_once()
            connection.__exit__.assert_called_once()

    def test_capture_refuses_existing_output_before_importing_wx(self):
        import grabber
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'existing.png'
            path.write_bytes(b'keep')
            with patch('grabber.capture') as capture, contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                grabber.main(['--output',str(path)])
            capture.assert_not_called()
            self.assertEqual(path.read_bytes(),b'keep')


@unittest.skipUnless(importlib.util.find_spec('scapy'),'optional scapy not installed')
class PcapTests(unittest.TestCase):
    def test_offline_packet_count_and_no_overwrite(self):
        from floodz import write_capture
        from scapy.utils import rdpcap
        from scapy.layers.inet import IP
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'sample.pcap'
            write_capture(path,3)
            packets=rdpcap(str(path))
            self.assertEqual(len(packets),3)
            self.assertEqual(packets[0][IP].dst,'192.0.2.2')
            with self.assertRaises(FileExistsError):
                write_capture(path,3)

    def test_ssid_layer_parsing_and_hidden_names(self):
        from scapy.layers.dot11 import Dot11,Dot11Elt,Dot11ProbeReq
        from hiddenwifi import extract_ssid
        packet=Dot11(type=0,subtype=4)/Dot11ProbeReq()/Dot11Elt(ID=1,info=b'abc')/Dot11Elt(ID=0,info=b'LAB')
        self.assertEqual(extract_ssid(packet),'LAB')
        self.assertIsNone(extract_ssid(Dot11(type=0,subtype=4)/Dot11ProbeReq()/Dot11Elt(ID=0,info=b'')))
        self.assertIsNone(extract_ssid(Dot11(type=2,subtype=0)/Dot11Elt(ID=0,info=b'ignore')))

if __name__=='__main__':
    unittest.main()
