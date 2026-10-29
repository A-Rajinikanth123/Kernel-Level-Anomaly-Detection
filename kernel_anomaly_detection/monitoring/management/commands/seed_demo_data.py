import random
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.utils import timezone
from monitoring.models import KernelEvent, AnomalyResult, SecurityAlert, MitigationLog, SystemMetric, AuditLog, MLModelMeta
from monitoring.ml.engine import detector
from monitoring.simulator.attack_scenarios import execute_attack_simulation

class Command(BaseCommand):
    help = 'Seeds database with realistic initial kernel events, alerts, metrics, and admin user'

    def handle(self, *args, **options):
        self.stdout.write("Initializing ML model baseline...")
        detector.load_or_train()

        # 1. Create Default Admin User
        admin_user, created = User.objects.get_or_create(username='admin')
        if created:
            admin_user.set_password('admin123')
            admin_user.email = 'admin@secops.local'
            admin_user.is_superuser = True
            admin_user.is_staff = True
            admin_user.first_name = 'Security'
            admin_user.last_name = 'Admin'
            admin_user.save()
            self.stdout.write(self.style.SUCCESS("Created admin user: admin / admin123"))
        else:
            self.stdout.write("Admin user already exists.")

        # Analyst user
        analyst_user, created = User.objects.get_or_create(username='analyst')
        if created:
            analyst_user.set_password('analyst123')
            analyst_user.email = 'analyst@secops.local'
            analyst_user.is_staff = True
            analyst_user.first_name = 'SOC'
            analyst_user.last_name = 'Analyst'
            analyst_user.save()
            self.stdout.write(self.style.SUCCESS("Created analyst user: analyst / analyst123"))

        # 2. Seed ML Model Metadata
        MLModelMeta.objects.get_or_create(
            model_name='Kernel-IsolationForest-v1.2',
            defaults={
                'algorithm': 'Isolation Forest (Ensemble Outlier Estimator)',
                'contamination': 0.04,
                'n_estimators': 120,
                'sample_count': 3000,
                'accuracy_score': 97.2,
                'is_active': True,
                'file_path': str(detector.model_path)
            }
        )

        # 3. Seed Normal Kernel Events across the last 2 hours
        now = timezone.now()
        normal_processes = [
            ('systemd', '/usr/lib/systemd/systemd', 'root', 'epoll_wait', 1),
            ('kworker/0:1', '[kernel]', 'root', 'schedule', 12),
            ('cron', '/usr/sbin/cron', 'root', 'clock_nanosleep', 450),
            ('sshd', '/usr/sbin/sshd', 'root', 'select', 980),
            ('nginx', '/usr/sbin/nginx', 'www-data', 'epoll_wait', 1120),
            ('postgres', '/usr/lib/postgresql/bin/postgres', 'postgres', 'semop', 1420),
            ('python3', '/usr/bin/python3', 'user', 'read', 2210),
            ('bash', '/bin/bash', 'user', 'write', 2560),
            ('dockerd', '/usr/bin/dockerd', 'root', 'futex', 890),
            ('dbus-daemon', '/usr/bin/dbus-daemon', 'messagebus', 'recvmsg', 630),
        ]

        self.stdout.write("Seeding normal kernel telemetry...")
        for i in range(40):
            p = random.choice(normal_processes)
            t_offset = now - timedelta(minutes=random.randint(1, 120), seconds=random.randint(0, 59))
            
            raw_stats = {
                'syscall_freq': float(random.randint(8, 35)),
                'cpu_usage': round(random.uniform(0.5, 12.0), 1),
                'mem_usage_mb': round(random.uniform(15.0, 85.0), 1),
                'thread_count': float(random.randint(1, 8)),
                'open_fds': float(random.randint(4, 25)),
                'file_op_rate': round(random.uniform(0.2, 5.0), 1),
                'net_conn_rate': round(random.uniform(0.0, 2.0), 1),
            }

            event = KernelEvent.objects.create(
                event_type='syscall' if i % 2 == 0 else 'process',
                process_id=p[4] + random.randint(0, 100),
                process_name=p[0],
                user=p[2],
                binary_path=p[1],
                syscall_name=p[3],
                target_path='/var/log/syslog' if i % 3 == 0 else '',
                is_privileged=(p[2] == 'root'),
                raw_data=raw_stats
            )
            event.timestamp = t_offset
            event.save(update_fields=['timestamp'])

            # Score with ML
            pred = detector.predict({
                'event_type': event.event_type,
                'process_name': event.process_name,
                'binary_path': event.binary_path,
                'is_privileged': event.is_privileged,
                'raw_data': raw_stats
            })

            res = AnomalyResult.objects.create(
                event=event,
                anomaly_score=pred['anomaly_score'],
                is_anomaly=pred['is_anomaly'],
                threat_level=pred['threat_level'],
                model_type='Isolation Forest',
                feature_vector=pred['feature_vector'],
                explanation=pred['explanation']
            )
            res.detected_at = t_offset
            res.save(update_fields=['detected_at'])

        # 4. Seed Time-Series System Metrics (Last 20 data points for live charts)
        self.stdout.write("Seeding historical system metrics...")
        for j in range(25):
            t_metric = now - timedelta(minutes=(25 - j) * 3)
            SystemMetric.objects.create(
                cpu_percent=round(random.uniform(14.0, 38.0), 1),
                memory_percent=round(random.uniform(42.0, 58.0), 1),
                syscalls_per_sec=random.randint(120, 340),
                active_processes=random.randint(110, 160),
                network_connections=random.randint(18, 45)
            )

        # 5. Seed Real-world Attack Scenarios so Alerts and SOC view look populated
        self.stdout.write("Simulating initial security incidents...")
        execute_attack_simulation('privilege_escalation', user=admin_user)
        execute_attack_simulation('ransomware_burst', user=admin_user)
        execute_attack_simulation('c2_beaconing', user=admin_user)
        execute_attack_simulation('sensitive_file_read', user=admin_user)

        self.stdout.write(self.style.SUCCESS("Database seeding completed successfully!"))
