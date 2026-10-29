from django.db import models
from django.contrib.auth.models import User
import uuid

class KernelEvent(models.Model):
    EVENT_TYPES = (
        ('syscall', 'System Call'),
        ('process', 'Process Event'),
        ('file', 'File Operation'),
        ('network', 'Network Connection'),
        ('privilege', 'Privilege Change'),
    )

    event_id = models.CharField(max_length=64, unique=True, default=uuid.uuid4, editable=False)
    event_type = models.CharField(max_length=20, choices=EVENT_TYPES, db_index=True)
    process_id = models.IntegerField(help_text="PID of the triggering process", db_index=True)
    process_name = models.CharField(max_length=255, db_index=True)
    parent_pid = models.IntegerField(null=True, blank=True)
    user = models.CharField(max_length=100, default='root')
    binary_path = models.CharField(max_length=512, blank=True, default='')
    syscall_name = models.CharField(max_length=100, blank=True, default='')
    target_path = models.CharField(max_length=512, blank=True, default='')
    ip_address = models.CharField(max_length=64, blank=True, default='')
    port = models.IntegerField(null=True, blank=True)
    is_privileged = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    raw_data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.event_type.upper()}] PID:{self.process_id} {self.process_name} - {self.syscall_name or self.target_path}"


class AnomalyResult(models.Model):
    THREAT_LEVELS = (
        ('NORMAL', 'Normal Activity'),
        ('LOW', 'Low Risk'),
        ('MEDIUM', 'Medium Risk'),
        ('HIGH', 'High Risk'),
        ('CRITICAL', 'Critical Threat'),
    )

    event = models.OneToOneField(KernelEvent, on_delete=models.CASCADE, related_name='anomaly_result')
    anomaly_score = models.FloatField(help_text="Calculated anomaly score between 0.0 and 1.0")
    is_anomaly = models.BooleanField(default=False, db_index=True)
    threat_level = models.CharField(max_length=20, choices=THREAT_LEVELS, default='NORMAL', db_index=True)
    model_type = models.CharField(max_length=100, default='Isolation Forest')
    feature_vector = models.JSONField(default=dict, blank=True)
    explanation = models.JSONField(default=dict, blank=True, help_text="Top deviating feature contributions")
    detected_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-detected_at']

    def __str__(self):
        return f"Score:{self.anomaly_score:.2f} ({self.threat_level}) - PID {self.event.process_id}"


class SecurityAlert(models.Model):
    STATUS_CHOICES = (
        ('ACTIVE', 'Active Threat'),
        ('INVESTIGATING', 'Under Investigation'),
        ('RESOLVED', 'Resolved / Mitigated'),
        ('FALSE_POSITIVE', 'False Positive'),
    )

    alert_id = models.CharField(max_length=64, unique=True)
    title = models.CharField(max_length=255)
    event = models.ForeignKey(KernelEvent, on_delete=models.SET_NULL, null=True, blank=True, related_name='alerts')
    anomaly_result = models.ForeignKey(AnomalyResult, on_delete=models.SET_NULL, null=True, blank=True)
    threat_level = models.CharField(max_length=20, choices=AnomalyResult.THREAT_LEVELS, default='HIGH', db_index=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE', db_index=True)
    description = models.TextField()
    recommended_action = models.TextField(blank=True, default='')
    mitigation_action_taken = models.CharField(max_length=255, blank=True, default='')
    process_killed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_alerts')

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.alert_id} - [{self.threat_level}] {self.title}"


class MitigationLog(models.Model):
    ACTION_TYPES = (
        ('KILL_PROCESS', 'Terminate Malicious Process'),
        ('QUARANTINE_FILE', 'Quarantine File / Binary'),
        ('BLOCK_IP', 'Block Network Connection / IP'),
        ('RESOLVE_MANUAL', 'Manual Review & Clearance'),
    )

    alert = models.ForeignKey(SecurityAlert, on_delete=models.CASCADE, related_name='mitigations')
    action_type = models.CharField(max_length=50, choices=ACTION_TYPES)
    target = models.CharField(max_length=255, help_text="PID, file path, or IP target")
    success = models.BooleanField(default=True)
    message = models.TextField()
    executed_at = models.DateTimeField(auto_now_add=True)
    executed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['-executed_at']

    def __str__(self):
        return f"{self.action_type} on {self.target} - {'SUCCESS' if self.success else 'FAILED'}"


class SystemMetric(models.Model):
    cpu_percent = models.FloatField(default=0.0)
    memory_percent = models.FloatField(default=0.0)
    syscalls_per_sec = models.IntegerField(default=0)
    active_processes = models.IntegerField(default=0)
    network_connections = models.IntegerField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']


class AuditLog(models.Model):
    action = models.CharField(max_length=255)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    details = models.TextField(blank=True, default='')
    ip_address = models.CharField(max_length=50, default='127.0.0.1')
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']


class MLModelMeta(models.Model):
    model_name = models.CharField(max_length=100, default='Kernel-IsolationForest-v1')
    algorithm = models.CharField(max_length=50, default='Isolation Forest')
    contamination = models.FloatField(default=0.05)
    n_estimators = models.IntegerField(default=100)
    sample_count = models.IntegerField(default=1000)
    accuracy_score = models.FloatField(default=96.4)
    is_active = models.BooleanField(default=True)
    trained_at = models.DateTimeField(auto_now=True)
    file_path = models.CharField(max_length=512, blank=True, default='')

    def __str__(self):
        return f"{self.model_name} ({self.algorithm}) - Contam: {self.contamination}"
