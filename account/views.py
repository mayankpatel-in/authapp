from django.contrib.auth.hashers import make_password
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import User 


# API view for user registration using (simple JWT)
class UserRegistrationAPIView(APIView):  
    
    def post(self, request):
        data = request.data

        # Validate data here instead of using serializer
        email = data.get('email', None)
        password = data.get('password', None)
        role = data.get('role', User.SOL_SEEKER)  # assign defult value "solution seeker"

        if not email or not password:
            return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            return Response({'error': 'User with this email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        # Create the user
        user = User(email=email, role=role)
        user.password = make_password(password)
        user.save()

        return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)


from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate

# API view for user login (simple JWT)
class UserLoginAPIView(APIView):

    def post(self, request):
        data = request.data

        email = data.get('email', None)
        password = data.get('password', None)

        if not email or not password:
            return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate user
        user = authenticate(email=email, password=password)

        if user is None:
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)

        # Generate JWT token usig simple JWT package
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        return Response({'access': access_token, 'refresh': refresh_token}, status=status.HTTP_200_OK)
