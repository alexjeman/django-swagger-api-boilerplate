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
