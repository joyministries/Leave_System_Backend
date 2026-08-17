"""Custom exception handling for the leaves API."""

import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status as http_status

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    """
    Custom exception handler that formats all error responses in standardized JSON format.

    Returns:
        Response with status: 0 and a message describing the error
    """
    response = exception_handler(exc, context)

    if response is not None:
        # Log the error
        logger.error(
            "API Error: %s - Status: %s - Detail: %s",
            context.get("view", "Unknown view"),
            response.status_code,
            response.data,
        )

        # Format validation errors
        if response.status_code == http_status.HTTP_400_BAD_REQUEST:
            # Build a human-readable summary and keep per-field errors for the frontend
            errors = {}
            error_details = []

            if isinstance(response.data, dict):
                for field, field_errors in response.data.items():
                    if isinstance(field_errors, list):
                        errors[field] = [str(e) for e in field_errors]
                        for error in field_errors:
                            error_details.append(f"{field}: {str(error)}")
                    else:
                        errors[field] = str(field_errors)
                        error_details.append(f"{field}: {str(field_errors)}")
            elif isinstance(response.data, list):
                error_details = [str(e) for e in response.data]
                errors = {"non_field_errors": error_details}
            else:
                error_details = [str(response.data)]
                errors = {"detail": str(response.data)}

            error_message = " | ".join(error_details) if error_details else "Validation error"

            return Response(
                {
                    "status": 0,
                    "message": error_message,
                    "errors": errors,
                },
                status=response.status_code,
            )


        # Handle authentication errors
        elif response.status_code == http_status.HTTP_401_UNAUTHORIZED:
            return Response(
                {
                    "status": 0,
                    "message": "Authentication failed. Please provide valid credentials.",
                },
                status=response.status_code,
            )

        # Handle permission errors
        elif response.status_code == http_status.HTTP_403_FORBIDDEN:
            return Response(
                {
                    "status": 0,
                    "message": "You do not have permission to perform this action.",
                },
                status=response.status_code,
            )

        # Handle not found errors
        elif response.status_code == http_status.HTTP_404_NOT_FOUND:
            return Response(
                {
                    "status": 0,
                    "message": "Resource not found.",
                },
                status=response.status_code,
            )

        # Handle other HTTP errors
        else:
            error_message = (
                response.data
                if isinstance(response.data, str)
                else "An error occurred."
            )
            return Response(
                {
                    "status": 0,
                    "message": error_message,
                },
                status=response.status_code,
            )

    # If response is None, return a generic error response after logging the traceback
    logger.exception("Unhandled server exception in API: %s", exc)
    return Response(
        {
            "status": 0,
            "message": "An unexpected error occurred.",
        },
        status=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
    )
