#!/bin/bash

## Copyright 2025 Google. 
## This software is provided as-is, without warranty or representation for any use or purpose. 
## Your use of it is subject to your agreement with Google.  

# A wrapper script to securely initialize Terraform.
#
# It intelligently detects the project ID in the following order of precedence:
#   1. From the GOOGLE_CLOUD_PROJECT environment variable (from gcloud config).
#   2. From the TF_VAR_project_id environment variable.
#
# IMPORTANT: This script MUST be run using 'source' or '.' so it can
# set the TF_VAR_project_id environment variable for your current shell session.
#
# Example Usage:
#   source ./init.sh
#   . ./init.sh

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Project ID Detection Logic ---
PROJECT_ID=""
SOURCE_MSG=""

if [ -n "$GOOGLE_CLOUD_PROJECT" ]; then
  # 1. Prefer GOOGLE_CLOUD_PROJECT if it's set
  PROJECT_ID=$GOOGLE_CLOUD_PROJECT
  SOURCE_MSG="(detected from gcloud config 'GOOGLE_CLOUD_PROJECT')"
elif [ -n "$TF_VAR_project_id" ]; then
  # 2. Fallback to TF_VAR_project_id
  PROJECT_ID=$TF_VAR_project_id
  SOURCE_MSG="(detected from 'TF_VAR_project_id' environment variable)"
else
  # 3. If neither are set, exit with an error.
  echo "❌ Error: Project ID not found."
  echo "Please set your project using 'gcloud config set project <PROJECT_ID>'"
  echo "or by setting the 'TF_VAR_project_id' environment variable."
  exit 1
fi

# --- Confirmation Prompt ---
echo "Terraform project ID detected: ${PROJECT_ID} ${SOURCE_MSG}"
read -p "Do you want to proceed with this project? [Y/n] " response

# Default to 'Yes' if the user just hits Enter
if [[ "$response" =~ ^[Nn]$ ]]; then
  echo "Operation cancelled by user."
  exit 0
fi

# --- Set Environment for Terraform ---
# Export the variable so it's available for subsequent terraform commands
echo "✅ Setting TF_VAR_project_id for this shell session..."
export TF_VAR_project_id=$PROJECT_ID


# --- Original Script Logic (Backend Initialization) ---
SECRET_ID="tfstate-bucket-name"

echo "Fetching backend bucket name from Secret Manager..."
BUCKET_NAME=$(gcloud secrets versions access latest \
  --secret="${SECRET_ID}" \
  --project="${PROJECT_ID}" \
  --format='get(payload.data)' | tr -d '\n' | base64 -d)

if [ -z "$BUCKET_NAME" ]; then
  echo "❌ Error: Could not fetch bucket name from Secret Manager."
  echo "Ensure the secret '${SECRET_ID}' exists in project '${PROJECT_ID}'."
  exit 1
fi

echo "Successfully fetched bucket name: ${BUCKET_NAME}"
echo "------------------------------------------------"
echo "Initializing Terraform with remote GCS backend..."

# Initialize Terraform, passing the fetched bucket name via the -backend-config flag.
terraform init \
  -backend-config="bucket=${BUCKET_NAME}"

echo "------------------------------------------------"
echo "✅ Terraform initialization complete."
echo "You can now run 'terraform plan' or 'terraform apply' without extra arguments."

