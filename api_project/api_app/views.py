from rest_framework import viewsets
from rest_framework.generics import GenericAPIView, get_object_or_404
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from drf_util.decorators import serialize_decorator


from api_app.models import Category, Blog, Comment
from api_app.serializers import (CategorySerializer,
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