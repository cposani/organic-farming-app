from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, authenticate
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework import status
from .forms import CustomUserCreationForm
from django.utils.encoding import force_bytes
from django.conf import settings





# 🌱 Homepage
def home_view(request):
    return render(request, 'home.html')

# 🧑‍🌾 Farmer Registration (Template + Email Verification)
import logging
logger = logging.getLogger(__name__)



from django.conf import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.http import HttpResponse
from django.shortcuts import render
from .forms import CustomUserCreationForm
import logging

logger = logging.getLogger(__name__)

def register_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            try:
                user = form.save(commit=False)
                user.is_active = False
                user.email = form.cleaned_data.get('email')
                user.save()

                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)

                # 🌍 Use localhost in DEBUG, production domain otherwise
                if settings.DEBUG==True:
                    protocol = 'http'
                    domain = 'localhost:8000'
                else:
                    protocol = 'https'
                    domain = 'organic-farming-app.onrender.com'

                link = f"{protocol}://{domain}/activate/{uid}/{token}/"

                # 📧 Email logic based on DEBUG
                send_mail(
                        subject='Verify your email',
                        message=f'Hello, {user.username}, Welcome to Organic Farming!\nClick to verify: {link}',
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[user.email],
                        fail_silently=False,
                    )

                return render(request, 'email_sent.html', {'email': user.email})
            except Exception as e:
                logger.error(f"Registration error: {e}")
                return HttpResponse("Something went wrong", status=500)
        else:
            print("Form is NOT valid")
            print(form.errors.as_data())
    else:
        form = CustomUserCreationForm()

    return render(request, 'register.html', {'form': form})



# 🔐 Login Page
def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('home')
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})

# 📧 Email Verification via Template

from django.utils.encoding import force_str
def activate_account(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except Exception:
        user = None

    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return render(request, 'activation_success.html', {'username': user.username})
    else:
        return render(request, 'activation_failed.html')

# 🔑 Token-Based Login API (Optional for mobile or frontend clients)
class CustomLogin(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        token = Token.objects.get(key=response.data['token'])
        return Response({'token': token.key})

# 🧑‍🌾 API Registration (Optional if using frontend)
class RegisterUser(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')

        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=username, password=password, email=email)
        user.is_active = False
        user.save()

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        domain = get_current_site(request).domain
        link = f"http://{domain}/activate/{uid}/{token}/"

        send_mail(
            subject='Verify your email',
            message=f'Hello, {user.username}, Welcome to Organic Farming! "Cultivating Tomorrow, Organically"\nClick the link to verify your account: {link}',
            from_email='noreply@yourdomain.com',
            recipient_list=[email],
            fail_silently=False,
        )

        return Response({'message': 'Verification email sent'}, status=status.HTTP_201_CREATED)
