import json
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from monitoring.models import KernelEvent, AnomalyResult, SecurityAlert, MitigationLog, MLModelMeta
from monitoring.ml.engine import detector
from monitoring.simulator.attack_scenarios import execute_attack_simulation

class KernelAnomalyDetectionTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='testadmin', password='testpassword123')
        detector.load_or_train()

    def test_ml_anomaly_detector_normal(self):
        """Tests that a standard benign system event is classified as NORMAL with low score."""
        benign_event = {
            'event_type': 'syscall',
            'process_name': 'bash',
            'user': 'user',
            'binary_path': '/bin/bash',
            'syscall_name': 'read',
            'is_privileged': False,
            'raw_data': {
                'syscall_freq': 14.0,
                'cpu_usage': 1.5,
                'mem_usage_mb': 25.0,
                'thread_count': 1.0,
                'open_fds': 4.0,
                'file_op_rate': 1.0,
                'net_conn_rate': 0.0,
            }
        }
        res = detector.predict(benign_event)
        self.assertIn('anomaly_score', res)
        self.assertIn('threat_level', res)
        self.assertLess(res['anomaly_score'], 0.60)

    def test_ml_anomaly_detector_privilege_escalation(self):
        """Tests that unauthorized privilege escalation raises anomaly score to HIGH or CRITICAL."""
        exploit_event = {
            'event_type': 'privilege',
            'process_name': 'dirtycow_exploit',
            'user': 'unprivileged',
            'binary_path': '/tmp/exploit',
            'syscall_name': 'setuid',
            'is_privileged': True,
            'raw_data': {
                'syscall_freq': 120.0,
                'cpu_usage': 45.0,
                'mem_usage_mb': 80.0,
                'thread_count': 6.0,
                'open_fds': 18.0,
                'file_op_rate': 12.0,
                'net_conn_rate': 1.0,
                'privilege_escalation': True,
                'suspicious_path': True,
                'sensitive_target': True
            }
        }
        res = detector.predict(exploit_event)
        self.assertGreaterEqual(res['anomaly_score'], 0.80)
        self.assertIn(res['threat_level'], ['HIGH', 'CRITICAL'])

    def test_attack_simulation_dispatch(self):
        """Tests execution of simulated attack and alert creation."""
        result = execute_attack_simulation('ransomware_burst', user=self.user)
        self.assertIsNotNone(result['alert_id'])
        self.assertIn(result['threat_level'], ['HIGH', 'CRITICAL'])

        # Verify DB records
        alert = SecurityAlert.objects.get(alert_id=result['alert_id'])
        self.assertEqual(alert.threat_level, result['threat_level'])
        self.assertEqual(alert.status, 'ACTIVE')

    def test_views_access_control(self):
        """Tests that unauthenticated users are redirected to login."""
        res = self.client.get(reverse('dashboard'))
        self.assertEqual(res.status_code, 302)

        login_success = self.client.login(username='testadmin', password='testpassword123')
        self.assertTrue(login_success)

        res_auth = self.client.get(reverse('dashboard'))
        self.assertEqual(res_auth.status_code, 200)

    def test_api_stats_endpoint(self):
        """Tests AJAX stats API returns JSON metrics."""
        self.client.login(username='testadmin', password='testpassword123')
        res = self.client.get(reverse('api_dashboard_stats'))
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertEqual(data['status'], 'success')
        self.assertIn('total_events', data)

    def test_alert_mitigation(self):
        """Tests mitigating an active security alert."""
        sim = execute_attack_simulation('reverse_shell', user=self.user)
        alert_id = sim['alert_id']
        self.client.login(username='testadmin', password='testpassword123')

        url = reverse('api_mitigate_alert', args=[alert_id])
        res = self.client.post(url, data=json.dumps({'action': 'QUARANTINE_FILE'}), content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.content)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['new_status'], 'RESOLVED')

        # Check DB
        updated_alert = SecurityAlert.objects.get(alert_id=alert_id)
        self.assertEqual(updated_alert.status, 'RESOLVED')
        self.assertEqual(updated_alert.mitigations.count(), 1)

    def test_admin_login_portal(self):
        """Tests admin login page rendering and authentication."""
        admin_user = User.objects.create_superuser('rootadmin', 'root@test.com', 'rootpass123')

        # GET admin login page
        res = self.client.get(reverse('admin_login'))
        self.assertEqual(res.status_code, 200)

        # POST valid credentials
        post_res = self.client.post(reverse('admin_login'), {
            'username': 'rootadmin',
            'password': 'rootpass123',
            'target': 'dashboard'
        })
        self.assertEqual(post_res.status_code, 302)
        self.assertTrue('_auth_user_id' in self.client.session)

