#!/bin/bash

# =========================================
# FatFox Security Toolkit Auto Update Script
# =========================================

# Ask for new version number
read -p "Enter new version (e.g., v1.2): " VERSION
if [ -z "$VERSION" ]; then
    echo "Version cannot be empty!"
    exit 1
fi

# Optional: custom commit message
read -p "Enter commit message for this update: " COMMIT_MSG
if [ -z "$COMMIT_MSG" ]; then
    COMMIT_MSG="Update to $VERSION: latest changes"
fi

# Stage all changes
git add .

# Commit changes
git commit -m "$COMMIT_MSG"

# Pull latest changes to avoid conflicts
git pull origin main

# Push changes to GitHub
git push origin main

# Tag the release version
git tag -a "$VERSION" -m "$COMMIT_MSG"
git push origin "$VERSION"

echo "✅ Updates pushed and tagged as $VERSION successfully!"
