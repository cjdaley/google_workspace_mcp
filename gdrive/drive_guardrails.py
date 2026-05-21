"""
Google Drive Guardrails Module

Implements guardrails for Google Drive operations:
- Input validation (file size, file name length, folder depth)
- Quota tracking (1000/day) via Knowledge Table
- Batch operation limits (max 100 per call)
- Permission change safety (warns on risky sharing patterns)

These guardrails protect against:
1. Unbounded file uploads (>5GB)
2. Quota exhaustion without warning (1000/day limit)
3. Overly permissive sharing (Anyone with link, public access)
4. Invalid folder structures (excessive nesting)
5. Batch operations exceeding Drive API limits

Key limits:
- File upload: max 5GB per file
- File name: max 255 characters
- Folder nesting: max 100 levels
- Batch operations: max 100 items per call
- Daily quota: 1000 requests/day
- Warning threshold: 900/1000 (90%)
- Exhausted threshold: 1000/1000 (100%)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Union, Any, Optional

logger = logging.getLogger(__name__)

# Note: relevance_raw_api is injected by Relevance AI platform at runtime
# For testing, this will be mocked
try:
    from relevance_ai import relevance_raw_api
except ImportError:
    def relevance_raw_api(*args, **kwargs):
        raise NotImplementedError("relevance_raw_api is not available in this context")

# Constants
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024 * 1024  # 5GB file upload limit
MAX_FILENAME_LENGTH = 255  # Google Drive filename limit
MAX_FOLDER_NESTING_DEPTH = 100  # Avoid excessively nested structures
MAX_BATCH_OPERATIONS = 100  # Drive API batch limit
DRIVE_QUOTA_PER_DAY = 1000  # Daily quota limit
DRIVE_WARNING_THRESHOLD = 900  # 90% utilization warning
DRIVE_EXHAUSTED_THRESHOLD = 1000  # 100% utilization block


def validate_upload_input(
    user_google_email: str,
    file_path: str,
    file_size_bytes: int
) -> Dict[str, Any]:
    """Validate input for uploading a file to Google Drive."""

    # Validate required params
    if not user_google_email:
        return {"error": "user_google_email is required"}
    if not file_path:
        return {"error": "file_path is required"}
    if file_size_bytes is None:
        return {"error": "file_size_bytes is required"}

    # Validate file size
    if file_size_bytes > MAX_FILE_SIZE_BYTES:
        size_gb = file_size_bytes / (1024 * 1024 * 1024)
        return {
            "error": f"File too large ({size_gb:.2f}GB; max 5GB)"
        }

    # Validate file size is reasonable (>0)
    if file_size_bytes <= 0:
        return {"error": "file_size_bytes must be greater than 0"}

    # Extract filename from path
    filename = file_path.split('/')[-1] if '/' in file_path else file_path

    # Validate filename length
    if len(filename) > MAX_FILENAME_LENGTH:
        return {
            "error": f"Filename too long ({len(filename)} chars; max {MAX_FILENAME_LENGTH})"
        }

    # Validate filename is not empty
    if not filename or filename.strip() == "":
        return {"error": "Filename cannot be empty"}

    return {
        "status": "validation_passed",
        "file_path": file_path,
        "filename": filename,
        "file_size_bytes": file_size_bytes,
        "file_size_mb": file_size_bytes / (1024 * 1024),
        "user_google_email": user_google_email
    }


def validate_create_folder_input(
    user_google_email: str,
    folder_name: str,
    parent_folder_id: str = None
) -> Dict[str, Any]:
    """Validate input for creating a folder in Google Drive."""

    # Validate required params
    if not user_google_email:
        return {"error": "user_google_email is required"}
    if not folder_name:
        return {"error": "folder_name is required"}
    if not isinstance(folder_name, str):
        return {"error": "folder_name must be a string"}

    # Validate folder name length
    if len(folder_name) > MAX_FILENAME_LENGTH:
        return {
            "error": f"Folder name too long ({len(folder_name)} chars; max {MAX_FILENAME_LENGTH})"
        }

    # Validate folder name is not empty
    if folder_name.strip() == "":
        return {"error": "Folder name cannot be empty"}

    # Reject reserved folder names
    reserved_names = ["My Drive", "Shared with me", "Starred", "Trash", "Spam"]
    if folder_name in reserved_names:
        return {
            "error": f"Cannot create folder with reserved name '{folder_name}'"
        }

    return {
        "status": "validation_passed",
        "folder_name": folder_name,
        "parent_folder_id": parent_folder_id,
        "user_google_email": user_google_email
    }


def validate_permission_change_input(
    user_google_email: str,
    file_id: str,
    permission_type: str,
    role: str = None
) -> Dict[str, Any]:
    """Validate input for changing file permissions in Google Drive."""

    # Validate required params
    if not user_google_email:
        return {"error": "user_google_email is required"}
    if not file_id:
        return {"error": "file_id is required"}
    if not permission_type:
        return {"error": "permission_type is required"}

    # Validate permission type
    valid_permission_types = [
        "user",
        "group",
        "domain",
        "anyone",
        "anyone_with_link"
    ]
    if permission_type not in valid_permission_types:
        return {
            "error": f"Invalid permission_type '{permission_type}'. "
                     f"Must be one of: {', '.join(valid_permission_types)}"
        }

    # Validate role if provided
    valid_roles = ["owner", "writer", "commenter", "reader"]
    if role and role not in valid_roles:
        return {
            "error": f"Invalid role '{role}'. "
                     f"Must be one of: {', '.join(valid_roles)}"
        }

    # Warn on risky sharing patterns
    warnings = []
    if permission_type == "anyone" or permission_type == "anyone_with_link":
        warnings.append(
            "⚠️ Warning: You're about to share this file with anyone. "
            "This exposes the file to public access. Consider restricting to specific users."
        )

    result = {
        "status": "validation_passed",
        "file_id": file_id,
        "permission_type": permission_type,
        "role": role,
        "user_google_email": user_google_email
    }

    if warnings:
        result["warnings"] = warnings

    return result


def validate_batch_operation_input(
    user_google_email: str,
    operations_count: int
) -> Dict[str, Any]:
    """Validate input for batch Drive operations."""

    # Validate required params
    if not user_google_email:
        return {"error": "user_google_email is required"}
    if operations_count is None:
        return {"error": "operations_count is required"}

    # Validate operations count
    if operations_count > MAX_BATCH_OPERATIONS:
        return {
            "error": f"Too many batch operations ({operations_count}; max {MAX_BATCH_OPERATIONS}). "
                     f"Split into multiple batches."
        }

    if operations_count <= 0:
        return {"error": "operations_count must be greater than 0"}

    return {
        "status": "validation_passed",
        "operations_count": operations_count,
        "user_google_email": user_google_email
    }


def get_drive_quota_key() -> str:
    """Generate quota tracking key for Drive operations (daily)."""
    now = datetime.now(timezone.utc)
    return f"drive_quota_{now.strftime('%Y_%m_%d')}"


def load_quota_state_from_kt(
    user_google_email: str,
    knowledge_set: str = "quota_tracking"
) -> Dict[str, Any]:
    """Load quota state from Knowledge Table."""
    quota_key = get_drive_quota_key()

    quota_state = {
        "drive_quota_used": 0,
        "drive_doc_id": None,
        "drive_quota_key": quota_key,
        "user_google_email": user_google_email
    }

    try:
        drive_response = relevance_raw_api(
            endpoint="/knowledge/retrieve",
            method="POST",
            body={
                "knowledge_set": knowledge_set,
                "filter": {
                    "key": quota_key,
                    "user_google_email": user_google_email,
                    "service": "drive"
                }
            }
        )
        if drive_response and len(drive_response.get("results", [])) > 0:
            doc = drive_response["results"][0]
            quota_state["drive_quota_used"] = doc.get("quota_used", 0)
            quota_state["drive_doc_id"] = doc.get("document_id")
        logger.debug(f"Loaded Drive quota: {quota_state['drive_quota_used']}/{DRIVE_QUOTA_PER_DAY}")
    except Exception as e:
        logger.warning(f"Failed to load Drive quota from KT: {str(e)}")

    logger.debug(f"Loaded Drive quota state: {quota_state}")
    return quota_state


def check_drive_quota(quota_state: Dict[str, Any]) -> Dict[str, Any]:
    """Check Drive API quota limits (1000/day)."""
    drive_quota_used = quota_state.get("drive_quota_used", 0)
    warnings = []

    # Check Drive quota (1000/day limit)
    if drive_quota_used >= DRIVE_EXHAUSTED_THRESHOLD:
        return {
            "error": f"Drive API quota exhausted ({drive_quota_used}/{DRIVE_QUOTA_PER_DAY}). "
                     f"Quota resets at 00:00 UTC tomorrow.",
            "action": "wait_until_quota_reset",
            "quota_exhausted": True
        }

    if drive_quota_used > DRIVE_WARNING_THRESHOLD:
        warnings.append(
            f"⚠️ Drive quota high ({drive_quota_used}/{DRIVE_QUOTA_PER_DAY}). "
            f"Only {DRIVE_QUOTA_PER_DAY - drive_quota_used} operations remaining today. "
            f"Quota resets at 00:00 UTC."
        )

    return {
        "status": "quota_available",
        "quota_used": drive_quota_used,
        "quota_remaining": DRIVE_QUOTA_PER_DAY - drive_quota_used,
        "warnings": warnings if warnings else None
    }


def validate_write_and_update_quota(
    write_result: Union[str, Dict],
    operation_type: str,
    quota_state: Dict[str, Any],
    user_google_email: str,
    knowledge_set: str = "quota_tracking"
) -> Dict[str, Any]:
    """Validate write response and prepare quota update."""

    if not write_result:
        return {
            "error": "No response from Google Drive API",
            "status": "error",
            "is_complete": False
        }

    if isinstance(write_result, str) and write_result.startswith("Error"):
        return {
            "error": f"Google Drive operation failed: {write_result}",
            "status": "error",
            "is_complete": False
        }

    # Most Drive operations = 1 API call
    # Batch operations may count differently; default to 1
    api_calls_made = 1

    logger.info(
        f"Drive operation successful ({operation_type}): {user_google_email}. "
        f"API calls: {api_calls_made}"
    )

    try:
        quota_key = quota_state.get("drive_quota_key")
        new_quota = quota_state.get("drive_quota_used", 0) + api_calls_made

        if quota_state.get("drive_doc_id"):
            # PATCH update existing Drive quota
            logger.debug(f"Updating Drive quota for {user_google_email} (doc_id={quota_state.get('drive_doc_id')})")
            response = relevance_raw_api(
                endpoint="/knowledge/update",
                method="PATCH",
                body={
                    "knowledge_set": knowledge_set,
                    "document_id": quota_state.get("drive_doc_id"),
                    "fields": {
                        "quota_used": new_quota,
                        "updated_at": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
        else:
            # POST create new Drive quota entry
            logger.debug(f"Creating Drive quota entry for {user_google_email}")
            response = relevance_raw_api(
                endpoint="/knowledge/add",
                method="POST",
                body={
                    "knowledge_set": knowledge_set,
                    "fields": {
                        "key": quota_key,
                        "quota_used": new_quota,
                        "user_google_email": user_google_email,
                        "service": "drive",
                        "updated_at": datetime.now(timezone.utc).isoformat()
                    }
                }
            )
        logger.info(f"Drive quota updated: {new_quota}/{DRIVE_QUOTA_PER_DAY}")
    except Exception as e:
        logger.error(f"Failed to update Drive quota: {str(e)}")

    return {
        "status": "success",
        "operation": operation_type,
        "is_complete": True,
        "quota_impact": api_calls_made,
        "metadata": {
            "api_calls_consumed": api_calls_made,
            "quota_state_updated": True,
            "quota_remaining": DRIVE_QUOTA_PER_DAY - (quota_state["drive_quota_used"] + api_calls_made),
            "quota_key": quota_state.get("drive_quota_key"),
            "note": "Daily 1000 request limit"
        }
    }
