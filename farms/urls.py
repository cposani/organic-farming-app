from django.urls import path
from .views import register_view,login_view, activate_account, home_view,CustomLogin,RegisterUser

urlpatterns = [
    path('', home_view, name='home'),
    path('register/', register_view, name='register'),
    path('login/', login_view, name='login'),
    path('activate/<uidb64>/<token>/', activate_account, name='activate'),

    # Optional API endpoints (for mobile or frontend clients)
    path('api/login/', CustomLogin.as_view(), name='api-login'),
    path('api/register/', RegisterUser.as_view(), name='api-register'),
]
