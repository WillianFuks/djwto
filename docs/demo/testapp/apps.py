from django.apps import AppConfig


class TestappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'testapp'

    def ready(self):
        import djwto.tokens as tokens

        def new_process_user(user):
            return {
                user.USERNAME_FIELD: user.get_username(),
                'email': user.email,
                'id': user.pk,
                # 'perms': tokens.process_perms(user)
                'perms': ['perm1']
            }

        tokens.process_user = new_process_user
