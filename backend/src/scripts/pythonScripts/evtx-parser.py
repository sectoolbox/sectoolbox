#!/usr/bin/env python3
"""
EVTX Parser - Parse Windows Event Log (.evtx) files
Extracts events with all fields and provides analysis
Auto-deletes the file after processing to save disk space
"""

import sys
import json
import os
from datetime import datetime
from collections import defaultdict
import xml.etree.ElementTree as ET

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
except ImportError:
    print(json.dumps({
        "error": "python-evtx library not installed. Install with: pip install python-evtx",
        "events": [],
        "metadata": {}
    }))
    sys.exit(1)


def parse_event_xml(xml_string):
    """Parse event XML and extract all relevant fields"""
    try:
        root = ET.fromstring(xml_string)
        
        # Define namespaces
        ns = {'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        
        # Extract System fields
        system = root.find('evt:System', ns)
        event_data = {}
        
        if system is not None:
            provider = system.find('evt:Provider', ns)
            event_id_elem = system.find('evt:EventID', ns)
            level_elem = system.find('evt:Level', ns)
            task_elem = system.find('evt:Task', ns)
            keywords_elem = system.find('evt:Keywords', ns)
            time_created = system.find('evt:TimeCreated', ns)
            event_record_id = system.find('evt:EventRecordID', ns)
            computer = system.find('evt:Computer', ns)
            security = system.find('evt:Security', ns)
            channel = system.find('evt:Channel', ns)
            
            event_data = {
                'provider': provider.get('Name') if provider is not None else '',
                'eventId': int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else 0,
                'level': int(level_elem.text) if level_elem is not None and level_elem.text else 0,
                'levelName': get_level_name(int(level_elem.text) if level_elem is not None and level_elem.text else 0),
                'task': int(task_elem.text) if task_elem is not None and task_elem.text else 0,
                'keywords': keywords_elem.text if keywords_elem is not None else '',
                'timestamp': time_created.get('SystemTime') if time_created is not None else '',
                'recordId': int(event_record_id.text) if event_record_id is not None and event_record_id.text else 0,
                'computer': computer.text if computer is not None else '',
                'userId': security.get('UserID') if security is not None else '',
                'channel': channel.text if channel is not None else ''
            }
        
        # Extract EventData fields
        event_data_elem = root.find('evt:EventData', ns)
        data_fields = {}
        
        if event_data_elem is not None:
            for data in event_data_elem.findall('evt:Data', ns):
                name = data.get('Name', f'Data{len(data_fields)}')
                value = data.text if data.text else ''
                data_fields[name] = value
        
        event_data['data'] = data_fields
        
        # Store raw XML for detailed view
        event_data['rawXml'] = xml_string
        
        return event_data
        
    except Exception as e:
        return {
            'error': f'Failed to parse event XML: {str(e)}',
            'rawXml': xml_string
        }


def get_level_name(level):
    """Convert level number to name"""
    levels = {
        0: 'LogAlways',
        1: 'Critical',
        2: 'Error',
        3: 'Warning',
        4: 'Information',
        5: 'Verbose'
    }
    return levels.get(level, f'Unknown({level})')


def extract_iocs(events):
    """Extract potential Indicators of Compromise from events"""
    iocs = {
        'ips': set(),
        'domains': set(),
        'users': set(),
        'processes': set(),
        'files': set(),
        'hashes': set()
    }
    
    import re
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    domain_pattern = re.compile(r'\b[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}\b', re.IGNORECASE)
    hash_pattern = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
    
    for event in events:
        # Extract from data fields
        for key, value in event.get('data', {}).items():
            value_str = str(value).lower()
            
            # IPs
            ips = ip_pattern.findall(value)
            iocs['ips'].update(ips)
            
            # Domains
            domains = domain_pattern.findall(value)
            iocs['domains'].update([d[0] if isinstance(d, tuple) else d for d in domains])
            
            # Hashes
            hashes = hash_pattern.findall(value)
            iocs['hashes'].update(hashes)
            
            # Users (common field names)
            if 'user' in key.lower() or 'account' in key.lower():
                if value and value != '-':
                    iocs['users'].add(value)
            
            # Processes
            if 'process' in key.lower() or 'image' in key.lower():
                if value and value.endswith('.exe'):
                    iocs['processes'].add(value)
            
            # Files
            if 'file' in key.lower() or 'path' in key.lower():
                if value and ('\\' in value or '/' in value):
                    iocs['files'].add(value)
    
    # Convert sets to sorted lists
    return {
        'ips': sorted(list(iocs['ips']))[:100],  # Limit to prevent huge outputs
        'domains': sorted(list(iocs['domains']))[:100],
        'users': sorted(list(iocs['users']))[:100],
        'processes': sorted(list(iocs['processes']))[:100],
        'files': sorted(list(iocs['files']))[:100],
        'hashes': sorted(list(iocs['hashes']))[:50]
    }


def detect_threats(events):
    """Detect potential security threats in events"""
    threats = []
    
    for event in events:
        event_id = event.get('eventId', 0)
        data = event.get('data', {})
        
        # Failed logins
        if event_id in [4625, 4771]:  # Failed logon, Kerberos pre-auth failed
            threats.append({
                'type': 'Failed Authentication',
                'severity': 'Warning',
                'eventId': event_id,
                'timestamp': event.get('timestamp'),
                'details': f"Failed login attempt - User: {data.get('TargetUserName', 'Unknown')}, Computer: {event.get('computer')}"
            })
        
        # Account lockout
        elif event_id == 4740:
            threats.append({
                'type': 'Account Lockout',
                'severity': 'Critical',
                'eventId': event_id,
                'timestamp': event.get('timestamp'),
                'details': f"Account locked out - User: {data.get('TargetUserName', 'Unknown')}"
            })
        
        # Privilege escalation
        elif event_id in [4672, 4673, 4674]:
            threats.append({
                'type': 'Privilege Use',
                'severity': 'Warning',
                'eventId': event_id,
                'timestamp': event.get('timestamp'),
                'details': f"Special privileges assigned - User: {data.get('SubjectUserName', 'Unknown')}"
            })
        
        # Account creation
        elif event_id == 4720:
            threats.append({
                'type': 'Account Created',
                'severity': 'Information',
                'eventId': event_id,
                'timestamp': event.get('timestamp'),
                'details': f"User account created - User: {data.get('TargetUserName', 'Unknown')}"
            })
        
        # Group membership change
        elif event_id in [4728, 4732, 4756]:
            threats.append({
                'type': 'Group Membership Change',
                'severity': 'Warning',
                'eventId': event_id,
                'timestamp': event.get('timestamp'),
                'details': f"User added to security group - User: {data.get('MemberName', 'Unknown')}, Group: {data.get('TargetUserName', 'Unknown')}"
            })
        
        # Service installation
        elif event_id in [4697, 7045]:
            threats.append({
                'type': 'Service Installed',
                'severity': 'Warning',
                'eventId': event_id,
                'timestamp': event.get('timestamp'),
                'details': f"Service installed - Service: {data.get('ServiceName', 'Unknown')}"
            })
        
        # PowerShell execution
        elif event_id in [4103, 4104]:
            threats.append({
                'type': 'PowerShell Execution',
                'severity': 'Information',
                'eventId': event_id,
                'timestamp': event.get('timestamp'),
                'details': f"PowerShell script executed"
            })
        
        # Process creation (Sysmon)
        elif event_id == 1:
            command_line = data.get('CommandLine', '')
            if any(sus in command_line.lower() for sus in ['powershell', 'cmd.exe', 'wscript', 'mshta']):
                threats.append({
                    'type': 'Suspicious Process',
                    'severity': 'Information',
                    'eventId': event_id,
                    'timestamp': event.get('timestamp'),
                    'details': f"Suspicious process: {data.get('Image', 'Unknown')}"
                })
    
    return threats[:1000]  # Limit threats


def analyze_events(events):
    """Perform analysis on events"""
    if not events:
        return {}
    
    # Event ID frequency
    event_id_counts = defaultdict(int)
    level_counts = defaultdict(int)
    provider_counts = defaultdict(int)
    computer_counts = defaultdict(int)
    user_counts = defaultdict(int)
    hourly_counts = defaultdict(int)
    
    for event in events:
        event_id_counts[event.get('eventId', 0)] += 1
        level_counts[event.get('levelName', 'Unknown')] += 1
        provider_counts[event.get('provider', 'Unknown')] += 1
        computer_counts[event.get('computer', 'Unknown')] += 1
        
        user = event.get('userId', '')
        if user and user != '-':
            user_counts[user] += 1
        
        # Hour bucket
        timestamp = event.get('timestamp', '')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                hour = dt.strftime('%Y-%m-%d %H:00')
                hourly_counts[hour] += 1
            except:
                pass
    
    # Sort and get top items
    top_event_ids = sorted(event_id_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    top_providers = sorted(provider_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    top_computers = sorted(computer_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    
    return {
        'topEventIds': [{'eventId': k, 'count': v} for k, v in top_event_ids],
        'levelDistribution': dict(level_counts),
        'topProviders': [{'provider': k, 'count': v} for k, v in top_providers],
        'topComputers': [{'computer': k, 'count': v} for k, v in top_computers],
        'topUsers': [{'user': k, 'count': v} for k, v in top_users],
        'timeline': sorted([{'time': k, 'count': v} for k, v in hourly_counts.items()], key=lambda x: x['time'])
    }


def parse_evtx_file(filepath):
    """Parse EVTX file and return all events with analysis"""
    events = []
    
    try:
        with evtx.Evtx(filepath) as log:
            for record in log.records():
                try:
                    xml_string = record.xml()
                    event = parse_event_xml(xml_string)
                    events.append(event)
                except Exception as e:
                    # Skip problematic records
                    continue
        
        # Perform analysis
        analysis = analyze_events(events)
        iocs = extract_iocs(events)
        threats = detect_threats(events)
        
        return {
            'events': events,
            'metadata': {
                'totalEvents': len(events),
                'filename': os.path.basename(filepath),
                'filesize': os.path.getsize(filepath)
            },
            'analysis': analysis,
            'iocs': iocs,
            'threats': threats
        }
        
    except Exception as e:
        return {
            'error': f'Failed to parse EVTX file: {str(e)}',
            'events': [],
            'metadata': {}
        }


def main():
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'No file path provided'}))
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    if not os.path.exists(filepath):
        print(json.dumps({'error': f'File not found: {filepath}'}))
        sys.exit(1)
    
    # Parse the file
    result = parse_evtx_file(filepath)
    
    # Output result as JSON
    print(json.dumps(result, default=str))
    
    # Delete the file after processing
    try:
        os.remove(filepath)
    except Exception as e:
        # Log error but don't fail the script
        pass


if __name__ == '__main__':
    main()
