#!/usr/bin/env python
# -*- coding:utf-8 -*-


import os
import sys
from django.core.wsgi import get_wsgi_application


reload(sys)
sys.setdefaultencoding('utf8')

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "apply_for_channel.settings")
application = get_wsgi_application()
