# Notes for creating Django RESTful API with Swagger and extended Users + JWT token authentication Boilerplate (fresh django install)

# create environment
```
python3 -m venv py38
```

# activate environment
```
source py38/bin/activate
```

# install dependencies from requirements.txt
```
pip install -r requirements.txt
```

# creating a new project
```
django-admin startproject api_project
mv api_project server
```

# create postgres docker container
```
docker run --name postgres_server -p 5432:5432  -e POSTGRES_PASSWORD=password123 postgres
```

# list local docker containers
```
docker container ls --all
```

# bash into the container to run postgres
```
docker start [container id]
docker exec -it [container id] bash
psql -U postgres
CREATE DATABASE my_postgres_db;
```

# SQL setup in django settings.py
```
cd server
```

# Add db connection and settings settings for the installed packages
``` 
""" api_project/settings.py """

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'my_postgres_db',
        'USER': 'postgres',
        'PASSWORD': '9RZjw6DR8zQgrKYWu3Np',
        'HOST': '127.0.0.1',
        'PORT': '5432',
    }
}
```

# migrate schema and create django admin user
```
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

# create app
```
cd api_project
mkdir apps
cd apps
django-admin startapp users
django-admin startapp common
django-admin startapp restful_api
```

# write app models, serializers, views, endpoints

## apps/restful_api model, serializer, endpoint

``` 
""" apps/restful_api/models.py """

from django.db import models


class Category(models.Model):
    title = models.CharField(max_length=100, db_index=True)
    slug = models.SlugField(max_length=100, db_index=True)

    def __str__(self):
        return 'Category: {}'.format(self.title)


class Blog(models.Model):
    title = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True)
    body = models.TextField()
    posted = models.DateField(db_index=True, auto_now_add=True)
    category = models.ForeignKey(Category, default=1, on_delete=models.CASCADE)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return 'Blog: {}, Status: {}'.format(
            self.title, "enabled" if self.enabled else "disabled"
        )


class Comment(models.Model):
    text = models.TextField()
    blog_id = models.ForeignKey(
        Blog, related_name='commentitem', on_delete=models.CASCADE
    )

    def __str__(self):
        return '{}...'.format(self.text[:50])

```

``` 
""" apps/restful_api/admin.py """

from django.contrib import admin
from apps.restful_api.models import Blog, Category, Comment

admin.site.register(Blog)
admin.site.register(Category)
admin.site.register(Comment)

```

``` 
""" apps/restful_api/serializers.py """

from django.contrib.auth.models import User
from rest_framework import serializers

from apps.restful_api.models import Category, Blog, Comment


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'


class BlogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blog
        fields = '__all__'


class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = '__all__'

```

``` 
""" apps/restful_api/views.py """

from rest_framework import viewsets
from rest_framework.generics import GenericAPIView, get_object_or_404
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from drf_util.decorators import serialize_decorator


from apps.restful_api.models import Category, Blog, Comment
from apps.restful_api.serializers import (CategorySerializer,
                                          BlogSerializer,
                                          CommentSerializer)


class CategoryViewSet(viewsets.ModelViewSet):
    serializer_class = CategorySerializer
    queryset = Category.objects.all()


class BlogListView(GenericAPIView):
    serializer_class = BlogSerializer

    permission_classes = (AllowAny,)
    authentication_classes = ()

    def get(self, request):
        blogs = Blog.objects.all()
        return Response(BlogSerializer(blogs, many=True).data)

    @serialize_decorator(BlogSerializer)
    def post(self, request):
        validated_data = request.serializer.validated_data

        blog = Blog.objects.create(
            title=validated_data['title'],
            slug=validated_data['slug'],
            body=validated_data['body'],
            enabled=validated_data['enabled'],
            category=validated_data['category']
        )
        blog.save()

        return Response(BlogSerializer(blog).data)


class BlogItemView(GenericAPIView):
    serializer_class = BlogSerializer
    queryset = ''
    permission_classes = (AllowAny,)
    authentication_classes = ()

    def get(self, request, pk):
        comments = Blog.objects.get(id=pk).commentitem.all().values()
        blog = get_object_or_404(Blog.objects.filter(pk=pk))

        context = {'blog': BlogSerializer(blog).data, 'comments': comments}
        return Response(context, content_type='application/json')


class CommentListView(GenericAPIView):
    serializer_class = CommentSerializer

    permission_classes = (AllowAny,)
    authentication_classes = ()

    @serialize_decorator(CommentSerializer)
    def post(self, request):
        validated_data = request.serializer.validated_data

        comment = Comment.objects.create(
            text=validated_data['text'],
            blog_id=validated_data['blog_id']
        )
        comment.save()

        return Response(CommentSerializer(comment).data)

```

``` 
""" apps/restful_api/urls.py """

from django.urls import path

from apps.restful_api.views import (CategoryViewSet,
                                    BlogListView,
                                    BlogItemView,
                                    CommentListView)
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'categories', CategoryViewSet, basename='category')

urlpatterns = router.urls

urlpatterns += [
    path('blog/', BlogListView.as_view(), name='blog_list'),
    path('comment/', CommentListView.as_view(), name='comment_list'),
    path('blog/<int:pk>/', BlogItemView.as_view(), name='blog_item'),
]

```

## apps/users model, serializer, views, endpoint

``` 
""" apps/users/model.py """

from django.db import models

```

``` 
""" apps/users/serializers.py """

from django.contrib.auth.models import User
from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ("first_name", "last_name", "username", "password",)

```

``` 
""" apps/users/serializers.py """

from django.contrib.auth.models import User
from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ("first_name", "last_name", "username", "password",)

```

``` 
""" apps/users/views.py """

from django.contrib.auth.models import User
from drf_util.decorators import serialize_decorator
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.users.serializers import UserSerializer


class RegisterUserView(GenericAPIView):
    serializer_class = UserSerializer

    permission_classes = (AllowAny,)
    authentication_classes = ()

    @serialize_decorator(UserSerializer)
    def post(self, request):
        validated_data = request.serializer.validated_data

        user = User.objects.create(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            username=validated_data['username'],
            is_superuser=True,
            is_staff=True
        )
        user.set_password(validated_data['password'])
        user.save()

        return Response(UserSerializer(user).data)

```

``` 
""" apps/users/urls.py """

from django.urls import path

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from apps.users.views import RegisterUserView

urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='token_register'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]

```

## apps/common exceptions, helpers...
```
mkdir apps/common/fixtures
```
``` 
""" apps/common/fixtures/initial_data.json """

[
  {
    "model": "auth.user",
    "pk": 1,
    "fields": {
      "email": "user1@email.com",
      "first_name": "first_name1",
      "last_name": "last_name1",
      "username": "username1",
      "is_superuser": false,
      "is_staff": false
    }
  }
]

```

``` 
""" apps/common/exceptions.py """

from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.views import exception_handler


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if isinstance(exc, AuthenticationFailed):
        return Response(response.data, status=status.HTTP_401_UNAUTHORIZED)

    return response

```

``` 
""" apps/common/helpers.py """

from collections import OrderedDict

from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework.permissions import AllowAny
from rest_framework.utils.serializer_helpers import ReturnDict, ReturnList

from collections.abc import Iterable
from typing import Dict, List

from django.conf import settings
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
import traceback

DICTIONARY_TYPES = [dict, OrderedDict, ReturnDict]
LIST_TYPES = [list, ReturnList]

schema_view = get_schema_view(
    openapi.Info(
        title="API Documentation",
        default_version='v1',
        description="Enjoy",
    ),
    validators=['ssv'],
    public=True,
    permission_classes=(AllowAny,)
)


def send_html_message(emails: List, title: str, template_path: str, context: Dict) -> None:
    """
    Send email by text template
    :param title: title message
    :param emails: list of receivers
    :param template_path: path to template, from templates/emails folder
    :param context: some context for template
    :return: boolean value
    Example : send_html_message(
                                ["test@gmail.com", ],
                                "Title test",
                                "emails/template_message.html",
                                {"test_text": "test test test"}
                                )
    """
    if isinstance(emails, str) or not isinstance(emails, Iterable):
        emails = [emails]
    html = render_to_string(template_path, context)

    msg = EmailMessage(
        title,
        html,
        to=emails,
        from_email='Tribes <%s>' % settings.EMAIL_HOST_USER
    )
    msg.content_subtype = 'html'
    try:
        msg.send()
    except Exception:
        traceback.print_exc()


def elastic_text_search(field: str, value: str):
    return {
        'bool': {
            "should": [
                {
                    'match': {
                        field: {
                            'query': value,
                            'operator': 'or'
                        }
                    }
                },
                {
                    'bool': {
                        'must': [
                            {'prefix': {
                                field: item
                            }} for item in value.lower().split(' ')
                        ]
                    }
                },
                {
                    "fuzzy": {
                        field: {
                            "value": value,
                            "boost": 1.0,
                            "fuzziness": 2,
                            "prefix_length": 0,
                            "max_expansions": 100
                        }
                    }
                }
            ]
        }
    }

```

``` 
""" apps/common/middlewares.py """

from django.utils.translation import gettext as _
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.utils import translation
import logging
import traceback

logger = logging.getLogger(__name__)


class ApiMiddleware(MiddlewareMixin):
    @staticmethod
    def process_request(request):
        request.LANGUAGE_CODE = translation.get_language()

    @staticmethod
    def process_exception(request, response):
        logger.error(traceback.format_exc())

        return JsonResponse({
            'exception': str(response),
            'detail': _('Something Went Wrong. Please contact support')
        }, status=500)

```

``` 
""" apps/common/permissions.py """

from rest_framework.permissions import BasePermission, SAFE_METHODS


class ReadOnly(BasePermission):
    def has_permission(self, request, view):
        return bool(request.method in SAFE_METHODS) and bool(request.user and request.user.is_authenticated)

```

``` 
""" apps/common/testings.py """

from django.test.runner import DiscoverRunner


class NoDbTestRunner(DiscoverRunner):
    """ A test runner to test without database creation/deletion """

    def setup_databases(self, **kwargs):
        pass

    def teardown_databases(self, old_config, **kwargs):
        pass

```

``` 
""" apps/common/tests.py """

from django.test import TestCase
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from django.contrib.auth.models import User


class TestCommon(TestCase):
    fixtures = ['initial_data']

    def setUp(self) -> None:
        self.client = APIClient()
        # check data in fixture json file
        self.test_user1 = User.objects.get(email="user1@email.com")

    def test_health_view(self):
        response = self.client.get(reverse('health_view'), )
        self.assertEqual(response.status_code, 200)

    def test_protected_view(self):
        self.client.force_authenticate(user=self.test_user1)
        response = self.client.get(reverse('protected_view'), )
        self.assertEqual(response.status_code, 200)

```

``` 
""" apps/common/urls.py """

from django.urls import path

from apps.common.views import HealthView, ProtectedTestView

urlpatterns = [
    path("health", HealthView.as_view(), name='health_view'),
    path("protected", ProtectedTestView.as_view(), name='protected_view'),
]

```

``` 
""" apps/common/validators.py """

from django.utils.translation import gettext as _
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

DEFAULT_FIELD = "pk"


class ObjectValidator(object):

    def __init__(self, model, field=None):
        self.model = model
        self.field = field if field else DEFAULT_FIELD

    def __call__(self, value):
        if self.field == DEFAULT_FIELD:
            value = ObjectIdValidator().__call__(value)

        message = _("This object not exists")
        try:
            if self.model.objects.filter(**{self.field: value}).count():
                return value
        except ValidationError:
            message = _("Validation error")
        raise serializers.ValidationError(message)


class ObjectIdSerializer(serializers.Serializer):
    object_id = serializers.CharField(
        min_length=24, max_length=24, required=True)


class ObjectIdValidator(object):

    def __call__(self, value):
        serializer = ObjectIdSerializer(data={
            'object_id': value
        })
        if not serializer.is_valid():
            raise serializers.ValidationError(
                serializer.errors.get('object_id'))

        return value

```

``` 
""" apps/common/views.py """

# Create your views here.
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response


class HealthView(APIView):

    authentication_classes = ()
    permission_classes = (AllowAny,)

    def get(self, request):
        return Response({
            'live': True,
        })


class ProtectedTestView(APIView):

    def get(self, request):
        return Response({
            'live': True,
        })

```


# api_project URLS

``` 
""" api_project/urls.py """

"""api_project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include

from apps.common.helpers import schema_view

urlpatterns = [
    path("", schema_view.with_ui('swagger', cache_timeout=0),
         name='schema-swagger-ui'),
    path('admin/', admin.site.urls),
    path('common/', include("apps.common.urls")),
    path('blog/', include("apps.restful_api.urls")),
    path('users/', include("apps.users.urls")),
]

```

# api_project Settings
``` 
""" ADDED to api_project/settings.py """

WSGI_AUTO_RELOAD = True

DEBUG_LEVEL = "INFO"

 INSTALLED_APPS = [ 
     'django.contrib.admin', 
     'rest_framework', 
     'rest_framework.authtoken', 
     'corsheaders', 
     'drf_yasg', 
     'django_nose', 
     'django_extensions', 
     'apps.common', 
     'apps.users', 
     'apps.restful_api',

 TEMPLATES = [ 
     { 
         'DIRS': ["templates/"], 
    },
]

CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_HEADERS = (
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
    'token',
    'cache-control'
)

REST_FRAMEWORK = {
    'DATETIME_FORMAT': "%Y-%m-%dT%H:%M:%SZ",
    'DEFAULT_AUTHENTICATION_CLASSES': (
         'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
    ),
    'EXCEPTION_HANDLER': 'app_helper.exceptions.custom_exception_handler'
}

SWAGGER_SETTINGS = {
    'SECURITY_DEFINITIONS': {
        'Token': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header'
        }
    }
}

FIXTURE_DIRS = (
    'fixtures/',
)

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')


DATE_FORMAT = "%Y-%m-%d %H:%m"

TEST_RUNNER = 'django_nose.NoseTestSuiteRunner'

NOSE_ARGS = [
    '--with-coverage',
    '--cover-package=' + ','.join([app + '.views' for app in INSTALLED_APPS if app.startswith('.')]),
]


SESSION_ENGINE = 'django.contrib.sessions.backends.cache'

```
