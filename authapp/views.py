import jwt
import json
from django.conf import settings
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import User
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime, timedelta


# @csrf_exempt
def register(request):
    if request.method == 'POST':
        # Registration logic
        data = json.loads(request.body)
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        # Additional registration logic if needed

        try:
            user = User.objects.create_user(username=username, email=email, password=password)
            # Additional registration logic if needed
            print(user)

            # Generate JWT token
            payload = {'user_id': user.id}
            token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

            # Store token in session for subsequent requests
            request.session['token'] = token

            return JsonResponse({'message': 'User registered successfully'})
        except:
            return JsonResponse({'error_message': 'Failed to register user.'}, status=400)
    else:
        return JsonResponse({'error_message': 'Invalid request method.'}, status=405)


@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')

        user = authenticate(request, email=email, password=password)

        if user is not None:
            # User authenticated, generate JWT token
            payload = {
                'user_id': user.id,
                'exp': datetime.utcnow() + settings.JWT_EXPIRATION_DELTA  # Token expiration time
            }
            token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

            request.session['token'] = token  # Store token in session for subsequent requests

            return JsonResponse({'message': 'Login successful.'})
        else:
            return JsonResponse({'error_message': 'Invalid credentials.'}, status=401)
    else:
        return JsonResponse({'error_message': 'Invalid request method.'}, status=405)


@login_required
def user_profile(request):
    token = request.session.get('token')

    if token:
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            user_id = payload['user_id']

            # User is authenticated
            user = User.objects.get(id=user_id)
            username = user.username
            email = user.email
            return JsonResponse({'username': username, 'email': email})
        except jwt.ExpiredSignatureError:
            # Token expired
            logout(request)
            return JsonResponse({'error_message': 'Token expired.'}, status=401)
        except (jwt.DecodeError, User.DoesNotExist):
            # Invalid token or user not found
            logout(request)
            return JsonResponse({'error_message': 'Invalid token.'}, status=401)
    else:
        # Token not found in session
        return JsonResponse({'error_message': 'Token not found.'}, status=401)


@csrf_exempt
def logout_view(request):
    logout(request)
    return JsonResponse({'message': 'Logout successful.'})
