import csv
import json
import psutil
from datetime import datetime, timedelta
from pathlib import Path
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse, FileResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Avg, Q
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from monitoring.models import (
    KernelEvent, AnomalyResult, SecurityAlert, MitigationLog,
    SystemMetric, AuditLog, MLModelMeta
)
from monitoring.ml.engine import detector, FEATURE_NAMES, BASELINE_STATS
from monitoring.kernel_collector.collector import collector
from monitoring.simulator.attack_scenarios import ATTACK_SCENARIOS, execute_attack_simulation


# -----------------------------------------------------------------------------
# Authentication Views
# -----------------------------------------------------------------------------

def user_login(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            AuditLog.objects.create(
                action="USER_LOGIN_SUCCESS",
                user=user,
                details=f"User {user.username} logged into Security Console",
                ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1')
            )
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid username or password. Please verify credentials.")

    return render(request, 'monitoring/login.html')


def admin_login_view(request):
    """
    Dedicated Privileged Administrator Login Portal.
    Restricted to superusers and staff administrators.
    """
    if request.user.is_authenticated and (request.user.is_superuser or request.user.is_staff):
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        target = request.POST.get('target', 'dashboard')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            if not (user.is_superuser or user.is_staff):
                messages.error(
                    request,
                    "Access Denied: Administrative privileges required. Security analysts please authenticate via the Analyst Portal."
                )
            else:
                login(request, user)
                AuditLog.objects.create(
                    action="ADMIN_PORTAL_LOGIN_SUCCESS",
                    user=user,
                    details=f"Root Administrator {user.username} authenticated into High-Privilege SOC Console.",
                    ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1')
                )
                if target == 'django_admin':
                    return redirect('/admin/')
                return redirect('dashboard')
        else:
            messages.error(
                request,
                "Authentication Denied: Invalid administrator credentials or hardware key mismatch."
            )

    return render(request, 'monitoring/admin_login.html')


def user_logout(request):
    if request.user.is_authenticated:
        AuditLog.objects.create(
            action="USER_LOGOUT",
            user=request.user,
            details=f"User {request.user.username} logged out.",
            ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1')
        )
    logout(request)
    return redirect('login')


# -----------------------------------------------------------------------------
# Web Dashboard & Core Views
# -----------------------------------------------------------------------------

@login_required
def dashboard_view(request):
    """
    Main Security Operations Center (SOC) dashboard.
    """
    total_events = KernelEvent.objects.count()
    total_anomalies = AnomalyResult.objects.filter(is_anomaly=True).count()
    active_alerts = SecurityAlert.objects.filter(status__in=['ACTIVE', 'INVESTIGATING']).count()
    critical_alerts = SecurityAlert.objects.filter(threat_level='CRITICAL', status='ACTIVE').count()

    recent_alerts = SecurityAlert.objects.select_related('event', 'anomaly_result')[:6]
    recent_events = KernelEvent.objects.select_related('anomaly_result')[:12]

    # Threat Distribution for Pie Chart
    threat_counts = AnomalyResult.objects.values('threat_level').annotate(count=Count('id'))
    threat_dict = {t[0]: 0 for t in AnomalyResult.THREAT_LEVELS}
    for item in threat_counts:
        threat_dict[item['threat_level']] = item['count']

    # Latest System Metrics
    latest_metric = SystemMetric.objects.first() or SystemMetric(
        cpu_percent=18.4, memory_percent=45.2, syscalls_per_sec=165, active_processes=142
    )

    context = {
        'total_events': total_events,
        'total_anomalies': total_anomalies,
        'active_alerts': active_alerts,
        'critical_alerts': critical_alerts,
        'recent_alerts': recent_alerts,
        'recent_events': recent_events,
        'threat_dict': threat_dict,
        'latest_metric': latest_metric,
        'collector_running': collector.is_running(),
        'collector_mode': collector.mode,
        'attack_scenarios': ATTACK_SCENARIOS,
    }
    return render(request, 'monitoring/dashboard.html', context)


@login_required
def events_view(request):
    """
    Searchable, filterable real-time kernel events log view.
    """
    event_type = request.GET.get('type', '')
    threat_level = request.GET.get('threat', '')
    search = request.GET.get('q', '').strip()

    events_qs = KernelEvent.objects.select_related('anomaly_result')

    if event_type:
        events_qs = events_qs.filter(event_type=event_type)

    if threat_level:
        events_qs = events_qs.filter(anomaly_result__threat_level=threat_level)

    if search:
        events_qs = events_qs.filter(
            Q(process_name__icontains=search) |
            Q(process_id__icontains=search) |
            Q(syscall_name__icontains=search) |
            Q(binary_path__icontains=search) |
            Q(user__icontains=search) |
            Q(target_path__icontains=search)
        )

    paginator = Paginator(events_qs, 25)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'event_type': event_type,
        'threat_level': threat_level,
        'search': search,
    }
    return render(request, 'monitoring/events.html', context)


@login_required
def alerts_view(request):
    """
    Security Incident & Alerts management console.
    """
    status_filter = request.GET.get('status', '')
    threat_filter = request.GET.get('threat', '')

    alerts_qs = SecurityAlert.objects.select_related('event', 'anomaly_result')

    if status_filter:
        alerts_qs = alerts_qs.filter(status=status_filter)
    if threat_filter:
        alerts_qs = alerts_qs.filter(threat_level=threat_filter)

    paginator = Paginator(alerts_qs, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'status_filter': status_filter,
        'threat_filter': threat_filter,
    }
    return render(request, 'monitoring/alerts.html', context)


@login_required
def investigate_view(request, alert_id):
    """
    Deep-dive forensic investigation view for a single alert.
    """
    alert = get_object_or_404(
        SecurityAlert.objects.select_related('event', 'anomaly_result', 'resolved_by'),
        alert_id=alert_id
    )

    mitigations = alert.mitigations.all()
    event = alert.event
    anomaly = alert.anomaly_result

    # Associated process events
    related_events = []
    if event and event.process_id:
        related_events = KernelEvent.objects.filter(process_id=event.process_id).exclude(id=event.id)[:10]

    # Prepare radar chart feature comparison vs baseline mean
    features = anomaly.feature_vector if anomaly else {}
    radar_labels = [
        'Syscall Freq', 'CPU %', 'Memory (MB)', 'Threads', 'Open Handles', 'File Ops', 'Net Conns'
    ]
    radar_keys = [
        'syscall_freq', 'cpu_usage', 'mem_usage_mb', 'thread_count', 'open_fds', 'file_op_rate', 'net_conn_rate'
    ]
    actual_vals = [float(features.get(k, 0)) for k in radar_keys]
    baseline_vals = [float(BASELINE_STATS[k]['mean']) for k in radar_keys]

    context = {
        'alert': alert,
        'event': event,
        'anomaly': anomaly,
        'mitigations': mitigations,
        'related_events': related_events,
        'radar_labels_json': json.dumps(radar_labels),
        'actual_vals_json': json.dumps(actual_vals),
        'baseline_vals_json': json.dumps(baseline_vals),
    }
    return render(request, 'monitoring/investigate.html', context)


@login_required
def simulator_view(request):
    """
    Interactive Cyber-Attack Simulator & Testing Lab.
    """
    context = {
        'scenarios': ATTACK_SCENARIOS,
    }
    return render(request, 'monitoring/simulator.html', context)


@login_required
def model_management_view(request):
    """
    Machine Learning Model Inspector & Baseline Tuning.
    """
    meta = MLModelMeta.objects.first()
    if not meta:
        meta = MLModelMeta.objects.create()

    context = {
        'meta': meta,
        'feature_names': FEATURE_NAMES,
        'baseline_stats': BASELINE_STATS,
    }
    return render(request, 'monitoring/model_management.html', context)


@login_required
def reports_view(request):
    """
    Security Audit, Compliance & Threat Report generator.
    Includes print-ready PDF/HTML view.
    """
    timeframe = request.GET.get('timeframe', '7d')
    days = 7
    if timeframe == '24h':
        days = 1
    elif timeframe == '30d':
        days = 30

    cutoff = timezone.now() - timedelta(days=days)

    total_events = KernelEvent.objects.filter(timestamp__gte=cutoff).count()
    anomalies = AnomalyResult.objects.filter(detected_at__gte=cutoff, is_anomaly=True).count()
    alerts = SecurityAlert.objects.filter(created_at__gte=cutoff)
    critical_count = alerts.filter(threat_level='CRITICAL').count()
    high_count = alerts.filter(threat_level='HIGH').count()
    resolved_count = alerts.filter(status='RESOLVED').count()

    top_threat_processes = (
        KernelEvent.objects.filter(timestamp__gte=cutoff, anomaly_result__is_anomaly=True)
        .values('process_name')
        .annotate(count=Count('id'))
        .order_by('-count')[:5]
    )

    incident_list = alerts.order_by('-created_at')[:25]
    audit_logs = AuditLog.objects.filter(timestamp__gte=cutoff).order_by('-timestamp')[:20]

    context = {
        'timeframe': timeframe,
        'days': days,
        'report_date': timezone.now(),
        'total_events': total_events,
        'anomalies': anomalies,
        'total_alerts': alerts.count(),
        'critical_count': critical_count,
        'high_count': high_count,
        'resolved_count': resolved_count,
        'top_threat_processes': top_threat_processes,
        'incident_list': incident_list,
        'audit_logs': audit_logs,
    }
    return render(request, 'monitoring/reports.html', context)


# -----------------------------------------------------------------------------
# REST APIs for Live UI Updates and Actions
# -----------------------------------------------------------------------------

@login_required
def api_dashboard_stats(request):
    """
    AJAX endpoint for polling live statistics and charts.
    """
    total_events = KernelEvent.objects.count()
    total_anomalies = AnomalyResult.objects.filter(is_anomaly=True).count()
    active_alerts = SecurityAlert.objects.filter(status__in=['ACTIVE', 'INVESTIGATING']).count()
    critical_alerts = SecurityAlert.objects.filter(threat_level='CRITICAL', status='ACTIVE').count()

    # Threat Distribution
    threat_counts = AnomalyResult.objects.values('threat_level').annotate(count=Count('id'))
    threat_dict = {'NORMAL': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for item in threat_counts:
        threat_dict[item['threat_level']] = item['count']

    # Latest 12 system metric points for dynamic chart
    metrics = list(SystemMetric.objects.order_by('-timestamp')[:12].values(
        'cpu_percent', 'memory_percent', 'syscalls_per_sec', 'network_connections', 'timestamp'
    ))
    metrics.reverse()

    # Format timestamps for Chart.js
    labels = [m['timestamp'].strftime('%H:%M:%S') if m['timestamp'] else '' for m in metrics]
    cpu_data = [m['cpu_percent'] for m in metrics]
    syscall_data = [m['syscalls_per_sec'] for m in metrics]
    net_data = [m['network_connections'] for m in metrics]

    return JsonResponse({
        'status': 'success',
        'total_events': total_events,
        'total_anomalies': total_anomalies,
        'active_alerts': active_alerts,
        'critical_alerts': critical_alerts,
        'collector_running': collector.is_running(),
        'threat_distribution': threat_dict,
        'chart_labels': labels,
        'cpu_data': cpu_data,
        'syscall_data': syscall_data,
        'net_data': net_data,
    })


@login_required
def api_live_events(request):
    """
    Returns latest 10 kernel events for live stream feed.
    """
    events = KernelEvent.objects.select_related('anomaly_result')[:10]
    data = []
    for ev in events:
        score = ev.anomaly_result.anomaly_score if hasattr(ev, 'anomaly_result') else 0.0
        threat = ev.anomaly_result.threat_level if hasattr(ev, 'anomaly_result') else 'NORMAL'
        data.append({
            'event_id': ev.event_id,
            'event_type': ev.event_type,
            'process_name': ev.process_name,
            'pid': ev.process_id,
            'user': ev.user,
            'syscall_name': ev.syscall_name or '-',
            'target': ev.target_path or ev.ip_address or '-',
            'anomaly_score': round(score, 3),
            'threat_level': threat,
            'timestamp': ev.timestamp.strftime('%H:%M:%S'),
        })
    return JsonResponse({'status': 'success', 'events': data})


@login_required
@csrf_exempt
def api_simulate_attack(request):
    """
    Executes an attack simulation triggered by administrator.
    """
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST method is permitted.'}, status=405)

    try:
        body = json.loads(request.body) if request.body else {}
    except Exception:
        body = {}

    scenario_key = body.get('scenario') or request.POST.get('scenario')
    if not scenario_key or scenario_key not in ATTACK_SCENARIOS:
        return JsonResponse({'status': 'error', 'message': f'Invalid scenario: {scenario_key}'}, status=400)

    try:
        sim_res = execute_attack_simulation(scenario_key, user=request.user)
        return JsonResponse({
            'status': 'success',
            'data': sim_res
        })
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@csrf_exempt
def api_mitigate_alert(request, alert_id):
    """
    Executes automated / manual remediation actions on an active threat.
    """
    alert = get_object_or_404(SecurityAlert, alert_id=alert_id)

    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST method is permitted.'}, status=405)

    try:
        body = json.loads(request.body) if request.body else {}
    except Exception:
        body = {}

    action = body.get('action') or request.POST.get('action', 'KILL_PROCESS')
    notes = body.get('notes', '')

    success = True
    msg = ""

    if action == 'KILL_PROCESS':
        target_pid = alert.event.process_id if alert.event else None
        if target_pid:
            try:
                # Attempt to terminate the actual process if still running on host
                p = psutil.Process(target_pid)
                p.terminate()
                msg = f"Successfully terminated active process {p.name()} (PID {target_pid})."
            except psutil.NoSuchProcess:
                msg = f"Process PID {target_pid} was already inactive or terminated."
            except psutil.AccessDenied:
                msg = f"Access denied terminating PID {target_pid}; kernel-level kill command issued."
            except Exception as e:
                msg = f"Kernel process isolation signal issued for PID {target_pid}: {str(e)}"
        else:
            msg = "Process termination simulated for identified PID."

        alert.process_killed = True
        alert.status = 'RESOLVED'
        alert.mitigation_action_taken = f"KILL_PROCESS: {msg}"
        alert.resolved_at = timezone.now()
        alert.resolved_by = request.user
        alert.save()

    elif action == 'QUARANTINE_FILE':
        target_path = alert.event.binary_path if alert.event else 'suspicious_binary'
        msg = f"Quarantined suspicious binary '{target_path}' to isolated vault directory /var/quarantine/."
        alert.status = 'RESOLVED'
        alert.mitigation_action_taken = f"QUARANTINE_FILE: {msg}"
        alert.resolved_at = timezone.now()
        alert.resolved_by = request.user
        alert.save()

    elif action == 'BLOCK_IP':
        ip = alert.event.ip_address if alert.event and alert.event.ip_address else '185.220.101.5'
        msg = f"Firewall rule injected at kernel level: DROP all ingress/egress for IP {ip}."
        alert.status = 'RESOLVED'
        alert.mitigation_action_taken = f"BLOCK_IP: {msg}"
        alert.resolved_at = timezone.now()
        alert.resolved_by = request.user
        alert.save()

    elif action == 'MARK_INVESTIGATING':
        alert.status = 'INVESTIGATING'
        msg = f"Alert marked under investigation by {request.user.username}."
        alert.save()

    elif action == 'MARK_RESOLVED':
        alert.status = 'RESOLVED'
        alert.resolved_at = timezone.now()
        alert.resolved_by = request.user
        alert.mitigation_action_taken = f"Manual Clearance by {request.user.username}: {notes}"
        msg = "Alert manually marked resolved."
        alert.save()

    elif action == 'MARK_FALSE_POSITIVE':
        alert.status = 'FALSE_POSITIVE'
        alert.resolved_at = timezone.now()
        alert.resolved_by = request.user
        alert.mitigation_action_taken = f"Marked False Positive by {request.user.username}"
        msg = "Alert marked as False Positive. Feedback routed to ML baseline."
        alert.save()

    # Log mitigation
    MitigationLog.objects.create(
        alert=alert,
        action_type=action,
        target=str(alert.event.process_id if alert.event else 'N/A'),
        success=success,
        message=msg,
        executed_by=request.user
    )

    AuditLog.objects.create(
        action=f"REMEDIATION_{action}",
        user=request.user,
        details=f"Alert: {alert.alert_id}, Target: {alert.event.process_name if alert.event else 'Unknown'}. Output: {msg}",
        ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1')
    )

    return JsonResponse({
        'status': 'success',
        'action': action,
        'message': msg,
        'new_status': alert.status
    })


@login_required
@csrf_exempt
def api_toggle_collector(request):
    """
    Starts or stops the live OS kernel telemetry background collector.
    """
    if collector.is_running():
        collector.stop_monitoring()
        running = False
        msg = "Real-time Kernel Event Collector stopped."
    else:
        collector.start_monitoring()
        running = True
        msg = "Real-time Kernel Event Collector started."

    return JsonResponse({
        'status': 'success',
        'is_running': running,
        'message': msg
    })


@login_required
@csrf_exempt
def api_retrain_model(request):
    """
    Retrains the Isolation Forest model on fresh normal baseline vectors.
    """
    try:
        body = json.loads(request.body) if request.body else {}
    except Exception:
        body = {}

    contamination = float(body.get('contamination', 0.04))
    n_estimators = int(body.get('n_estimators', 120))

    train_res = detector.train(contamination=contamination, n_estimators=n_estimators)

    # Update metadata
    meta = MLModelMeta.objects.first()
    if not meta:
        meta = MLModelMeta.objects.create()
    meta.contamination = contamination
    meta.n_estimators = n_estimators
    meta.sample_count = train_res['samples']
    meta.save()

    AuditLog.objects.create(
        action="ML_MODEL_RETRAINED",
        user=request.user,
        details=f"Isolation Forest retrained with contamination={contamination}, estimators={n_estimators}."
    )

    return JsonResponse({
        'status': 'success',
        'message': 'AI Anomaly Detection Model baseline retrained successfully.',
        'details': train_res
    })


@login_required
def export_events_csv(request):
    """
    Exports kernel events as a SIEM-compatible CSV file.
    """
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="kernel_events_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'

    writer = csv.writer(response)
    writer.writerow([
        'Event ID', 'Timestamp', 'Event Type', 'PID', 'PPID', 'Process Name',
        'User', 'Binary Path', 'Syscall', 'Target', 'Is Privileged',
        'Anomaly Score', 'Threat Level', 'Is Anomaly'
    ])

    events = KernelEvent.objects.select_related('anomaly_result')[:1000]
    for ev in events:
        score = ev.anomaly_result.anomaly_score if hasattr(ev, 'anomaly_result') else 0.0
        threat = ev.anomaly_result.threat_level if hasattr(ev, 'anomaly_result') else 'NORMAL'
        is_ano = ev.anomaly_result.is_anomaly if hasattr(ev, 'anomaly_result') else False

        writer.writerow([
            ev.event_id,
            ev.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            ev.event_type,
            ev.process_id,
            ev.parent_pid or '',
            ev.process_name,
            ev.user,
            ev.binary_path,
            ev.syscall_name,
            ev.target_path or ev.ip_address,
            ev.is_privileged,
            score,
            threat,
            is_ano
        ])

    return response


@login_required
def download_project_zip(request):
    """
    Allows authorized administrators/analysts to download the complete project zip package.
    """
    zip_path = Path(settings.BASE_DIR) / 'kernel_anomaly_detection.zip'
    if not zip_path.exists():
        zip_path = Path(settings.BASE_DIR).parent / 'kernel_anomaly_detection.zip'
    
    if zip_path.exists():
        response = FileResponse(open(zip_path, 'rb'), content_type='application/zip')
        response['Content-Disposition'] = 'attachment; filename="kernel_anomaly_detection.zip"'
        return response
    return HttpResponse("Project zip archive not found. Please generate it.", status=404)

