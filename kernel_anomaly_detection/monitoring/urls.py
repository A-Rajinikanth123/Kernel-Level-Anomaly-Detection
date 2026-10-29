from django.urls import path
from monitoring import views

urlpatterns = [
    # Web UI Pages
    path('', views.dashboard_view, name='dashboard'),
    path('login/', views.user_login, name='login'),
    path('admin-login/', views.admin_login_view, name='admin_login'),
    path('logout/', views.user_logout, name='logout'),
    path('events/', views.events_view, name='events'),
    path('alerts/', views.alerts_view, name='alerts'),
    path('investigate/<str:alert_id>/', views.investigate_view, name='investigate'),
    path('simulator/', views.simulator_view, name='simulator'),
    path('model/', views.model_management_view, name='model_management'),
    path('reports/', views.reports_view, name='reports'),
    path('export/csv/', views.export_events_csv, name='export_csv'),
    path('download/zip/', views.download_project_zip, name='download_zip'),

    # REST APIs
    path('api/stats/', views.api_dashboard_stats, name='api_dashboard_stats'),
    path('api/overview', views.api_dashboard_stats, name='api_overview_legacy'),
    path('api/overview/', views.api_dashboard_stats, name='api_overview_slash'),
    path('api/events/live/', views.api_live_events, name='api_live_events'),
    path('api/simulate/', views.api_simulate_attack, name='api_simulate_attack'),
    path('api/alerts/<str:alert_id>/mitigate/', views.api_mitigate_alert, name='api_mitigate_alert'),
    path('api/collector/toggle/', views.api_toggle_collector, name='api_toggle_collector'),
    path('api/model/retrain/', views.api_retrain_model, name='api_retrain_model'),
]
