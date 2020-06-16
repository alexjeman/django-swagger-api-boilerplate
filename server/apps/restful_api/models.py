from django.db import models
from django.contrib.auth.models import User


class Category(models.Model):
    title = models.CharField(max_length=100, db_index=True)
    slug = models.SlugField(max_length=100, db_index=True)

    def __str__(self):
        return 'Category: {}'.format(self.title)


class Blog(models.Model):
    author = models.ForeignKey(
        User, related_name='blogitem', default=User, on_delete=models.CASCADE
    )
    title = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True)
    posted = models.DateField(db_index=True, auto_now_add=True)
    category = models.ForeignKey(Category, default=1, on_delete=models.CASCADE)
    body = models.TextField()
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return 'Blog: {}, Status: {}'.format(
            self.title, "enabled" if self.enabled else "disabled"
        )


class Comment(models.Model):
    blog = models.ForeignKey(
        Blog, related_name='commentitem', on_delete=models.CASCADE
    )
    author = models.ForeignKey(
        User, related_name='comments', default=User, on_delete=models.CASCADE
    )
    text = models.TextField()

    def __str__(self):
        return '{}...'.format(self.text[:50])
