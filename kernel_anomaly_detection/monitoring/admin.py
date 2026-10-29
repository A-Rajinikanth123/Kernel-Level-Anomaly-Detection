from django.contrib import admin
from monitoring.models import (
    KernelEvent, AnomalyResult, SecurityAlert, MitigationLog,
    SystemMetric, AuditLog, MLModelMeta
)

@admin.register(KernelEvent)
class KernelEventAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'event_type', 'process_id', 'process_name', 'user', 'syscall_name', 'is_privileged')
    list_filter = ('event_type', 'is_privileged', 'user')
    search_fields = ('process_name', 'process_id', 'syscall_name', 'binary_path')
    date_hierarchy = 'timestamp'


@admin.register(AnomalyResult)
class AnomalyResultAdmin(admin.ModelAdmin):
    list_display = ('event', 'anomaly_score', 'threat_level', 'is_anomaly', 'detected_at')
    list_filter = ('threat_level', 'is_anomaly')
    search_fields = ('event__process_name', 'event__process_id')


@admin.register(SecurityAlert)
class SecurityAlertAdmin(admin.ModelAdmin):
    list_display = ('alert_id', 'threat_level', 'status', 'title', 'process_killed', 'created_at')
    list_filter = ('threat_level', 'status', 'process_killed')
    search_fields = ('alert_id', 'title', 'description')


@admin.register(MitigationLog)
class MitigationLogAdmin(admin.ModelAdmin):
    list_display = ('alert', 'action_type', 'target', 'success', 'executed_at', 'executed_by')
    list_filter = ('action_type', 'success')


@admin.register(SystemMetric)
class SystemMetricAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'cpu_percent', 'memory_percent', 'syscalls_per_sec', 'active_processes', 'network_connections')


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'action', 'user', 'ip_address')
    search_fields = ('action', 'details')


@admin.register(MLModelMeta)
class MLModelMetaAdmin(admin.ModelAdmin):
    list_display = ('model_name', 'algorithm', 'contamination', 'n_estimators', 'accuracy_score', 'trained_at', 'is_active')
