from django.apps import AppConfig


class LeavesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'leaves'

    def ready(self):
        # Import signals to ensure they are registered
        import leaves.signals
