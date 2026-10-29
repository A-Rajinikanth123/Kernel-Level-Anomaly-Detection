import random
import time
from monitoring.kernel_collector.collector import collector

ATTACK_SCENARIOS = {
    'privilege_escalation': {
        'name': 'Privilege Escalation Attempt (setuid/capset)',
        'description': 'Simulates an attacker attempting to escalate user privileges to root/SYSTEM via setuid/capset manipulation.',
        'event_type': 'privilege',
        'process_name': 'linpeas_exploit',
        'binary_path': '/tmp/exploit_priv',
        'syscall_name': 'setuid',
        'target_path': '/proc/sys/kernel/core_pattern',
        'user': 'unprivileged_user',
        'is_privileged': True,
        'raw_data': {
            'syscall_freq': 95.0,
            'cpu_usage': 18.5,
            'mem_usage_mb': 52.0,
            'thread_count': 4.0,
            'open_fds': 14.0,
            'file_op_rate': 8.0,
            'net_conn_rate': 1.0,
            'privilege_escalation': True,
            'suspicious_path': True,
            'sensitive_target': True
        }
    },
    'ransomware_burst': {
        'name': 'Ransomware High-Velocity File Encryption',
        'description': 'Simulates rapid file access, encryption, and deletion across sensitive user documents directory.',
        'event_type': 'file',
        'process_name': 'cryptolocker.elf',
        'binary_path': '/tmp/.hidden_enc',
        'syscall_name': 'openat_write',
        'target_path': '/home/user/documents/financial_records.xlsx.locked',
        'user': 'user_workstation',
        'is_privileged': False,
        'raw_data': {
            'syscall_freq': 380.0,
            'cpu_usage': 78.0,
            'mem_usage_mb': 210.0,
            'thread_count': 16.0,
            'open_fds': 120.0,
            'file_op_rate': 240.0,
            'net_conn_rate': 2.0,
            'privilege_escalation': False,
            'suspicious_path': True,
            'sensitive_target': False
        }
    },
    'reverse_shell': {
        'name': 'Interactive Reverse Shell Injection',
        'description': 'Simulates an attacker spawning an interactive shell payload (/bin/sh / nc) communicating with a remote listener.',
        'event_type': 'process',
        'process_name': 'reverse_shell_nc',
        'binary_path': '/tmp/nc.traditional',
        'syscall_name': 'execve',
        'target_path': '/bin/sh',
        'ip_address': '185.220.101.5',
        'port': 4444,
        'user': 'www-data',
        'is_privileged': False,
        'raw_data': {
            'syscall_freq': 65.0,
            'cpu_usage': 12.0,
            'mem_usage_mb': 35.0,
            'thread_count': 2.0,
            'open_fds': 5.0,
            'file_op_rate': 3.0,
            'net_conn_rate': 15.0,
            'privilege_escalation': False,
            'suspicious_path': True,
            'sensitive_target': False
        }
    },
    'syscall_flood': {
        'name': 'Kernel Syscall Flood & Fork Bomb',
        'description': 'Simulates malicious high-frequency system call exhaustion and fork storm to destabilize kernel scheduling.',
        'event_type': 'syscall',
        'process_name': 'kernel_fuzzer_flood',
        'binary_path': '/dev/shm/fork_storm',
        'syscall_name': 'fork_clone',
        'target_path': '/sys/kernel/debug',
        'user': 'guest_session',
        'is_privileged': False,
        'raw_data': {
            'syscall_freq': 720.0,
            'cpu_usage': 94.0,
            'mem_usage_mb': 380.0,
            'thread_count': 64.0,
            'open_fds': 90.0,
            'file_op_rate': 12.0,
            'net_conn_rate': 0.0,
            'privilege_escalation': False,
            'suspicious_path': True,
            'sensitive_target': False
        }
    },
    'c2_beaconing': {
        'name': 'Rogue C2 Command & Control Beaconing',
        'description': 'Simulates persistent outbound kernel socket connections to unauthorized command-and-control server.',
        'event_type': 'network',
        'process_name': 'beacon_agent_x',
        'binary_path': '/var/tmp/.sysupdate',
        'syscall_name': 'connect',
        'target_path': 'socket:AF_INET',
        'ip_address': '194.26.29.112',
        'port': 8443,
        'user': 'system_service',
        'is_privileged': False,
        'raw_data': {
            'syscall_freq': 45.0,
            'cpu_usage': 8.5,
            'mem_usage_mb': 40.0,
            'thread_count': 3.0,
            'open_fds': 8.0,
            'file_op_rate': 4.0,
            'net_conn_rate': 42.0,
            'privilege_escalation': False,
            'suspicious_path': True,
            'sensitive_target': False
        }
    },
    'sensitive_file_read': {
        'name': 'Unauthorized Credential Database Exfiltration',
        'description': 'Simulates suspicious access to /etc/shadow or Windows SAM hive to extract hashed credentials.',
        'event_type': 'file',
        'process_name': 'dump_hashes',
        'binary_path': '/tmp/mimikatz_core',
        'syscall_name': 'openat',
        'target_path': '/etc/shadow',
        'user': 'local_user',
        'is_privileged': True,
        'raw_data': {
            'syscall_freq': 85.0,
            'cpu_usage': 15.0,
            'mem_usage_mb': 48.0,
            'thread_count': 2.0,
            'open_fds': 12.0,
            'file_op_rate': 15.0,
            'net_conn_rate': 0.0,
            'privilege_escalation': True,
            'suspicious_path': True,
            'sensitive_target': True
        }
    }
}

def execute_attack_simulation(scenario_key, user=None):
    """
    Executes a predefined or customized attack scenario.
    Returns the ingested event, anomaly result, and generated alert.
    """
    if scenario_key not in ATTACK_SCENARIOS:
        raise ValueError(f"Unknown scenario key: {scenario_key}")

    scenario = ATTACK_SCENARIOS[scenario_key]
    pid = random.randint(3100, 9999)
    ppid = random.randint(1000, 3099)

    event_payload = {
        'event_type': scenario['event_type'],
        'process_id': pid,
        'parent_pid': ppid,
        'process_name': scenario['process_name'],
        'user': scenario['user'],
        'binary_path': scenario['binary_path'],
        'syscall_name': scenario['syscall_name'],
        'target_path': scenario['target_path'],
        'ip_address': scenario.get('ip_address', ''),
        'port': scenario.get('port', None),
        'is_privileged': scenario['is_privileged'],
        'raw_data': scenario['raw_data']
    }

    result = collector.ingest_event(event_payload, triggered_by_user=user)
    return {
        'scenario': scenario['name'],
        'event_id': result['event'].event_id,
        'process_name': result['event'].process_name,
        'pid': result['event'].process_id,
        'anomaly_score': result['anomaly_result'].anomaly_score,
        'threat_level': result['anomaly_result'].threat_level,
        'alert_id': result['alert'].alert_id if result['alert'] else None,
        'details': scenario['description']
    }
