from django.urls import path
from .views import register, login_view, user_profile, logout_view

urlpatterns = [
    path('register/', register, name='register'),
    path('login/', login_view, name='login'),
    path('profile/', user_profile, name='user_profile'),
    path('logout/', logout_view, name='logout'),
]
