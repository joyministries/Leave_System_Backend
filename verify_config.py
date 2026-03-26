#!/usr/bin/env python
"""Quick verification that configuration is valid."""

import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "leavesystem.settings")

import django

django.setup()

from django.conf import settings

print("✓ Django settings loaded successfully!")
print(f"\nConfiguration:")
print(f"  DEBUG: {settings.DEBUG}")
print(f"  ALLOWED_HOSTS: {settings.ALLOWED_HOSTS}")
print(f"  EMAIL_HOST: {settings.EMAIL_HOST}")
print(f"  CORS_ALLOWED_ORIGINS: {settings.CORS_ALLOWED_ORIGINS}")
print(f"  CORS_ALLOW_ALL_ORIGINS: {settings.CORS_ALLOW_ALL_ORIGINS}")
print("\n✓ All configuration is valid!")
