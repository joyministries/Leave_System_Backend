# 🏢 Leave Management System – Backend API

A production-ready Django REST Framework backend for managing multi-institution employee leave requests, branch-scoped leave types, balances, approval workflows, dynamic RBAC, and transactional notifications.

---

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [RBAC & Data Scoping Architecture](#-rbac--data-scoping-architecture)
- [Branch-Specific & Allowed Leave Types](#-branch-specific--allowed-leave-types)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
- [Environment Configuration](#-environment-configuration)
- [Database Initialization & Seeding](#-database-initialization--seeding)
- [Running the Application](#-running-the-application)
- [Project Structure](#-project-structure)
- [API Overview](#-api-overview)
- [Management Commands](#-management-commands)
- [Testing](#-testing)
- [License](#-license)

---

## ✨ Features

### 🏛️ Multi-Institution Architecture
- Support for multiple branches/institutions (e.g. *Team Impact Christian University*, *Lambton Christian School*, *New Haven Academy*).
- Customizable institution settings: default role, self-cancel permission, maximum consecutive leave days, and dual-approval thresholds.
- **Branch-Specific Allowed Leave Types**: Each branch can selectively enable which leave types are available for its employees (e.g. enabling specific leave types while excluding unpaid leave).

### 🛡️ Dynamic Role-Based Access Control (RBAC)
- Fine-grained permission model (`Permission` and `Role`).
- Scoped data access via `Role.DataScope`:
  - **`GLOBAL`**: Cross-institution visibility (Admins, Directors).
  - **`INSTITUTION`**: Scoped strictly to the employee's own branch (Managers, HR).
  - **`OWN`**: Scoped strictly to the employee's own records (Staff).
- Flexible role assignment: APIs accept string role names (`"STAFF"`, `"MANAGER"`, `"ADMIN"`) as well as primary key IDs, and consistently serialize role names for seamless frontend consumption.
- Support for creating custom institution-specific roles without altering code.

### 🌴 Leave Management & Automated Balances
- **Entitlement Calculation**: Automatically tracks annual leave balances per employee per year.
- **Paid vs. Unpaid Allocation**: When an application exceeds remaining paid balance, excess days are flagged as `extra_unpaid_days` while approving the request.
- **Inclusive Duration Calculations**: Accurately computes working days and calendar ranges.
- **Document Attachments**: Upload and download supporting medical certificates or leave documents (AWS S3 signed URLs or local storage).

### ✍️ Approval & Cancellation Workflows
- Multi-role review: Branch Managers, HR, Directors, and Admins can approve or reject pending leave requests within their data scope with optional admin remarks.
- Self-cancellation by employees for pending requests, and administrative cancellation.

### 🔔 Notifications & Transactional Emails
- **In-App Notifications**: Real-time notification feed with unread counters and mark-as-read endpoints.
- **HTML Transactional Emails**: Automated emails triggered on submission, approval, rejection, and account creation via **Anymail / Resend**.

### 👥 Employee Lifecycle & Security
- **Email-as-Username**: Custom `Employee` user model using email as unique login identifier.
- **Invitation Flow**: Admin onboarded accounts start locked with unusable passwords; activated via time-limited, signed email links.
- **Soft Deletion**: Employees are flagged (`is_deleted=True`) to maintain full historical audit trails and leave records.
- **JWT Authentication**: Secure token authentication (access + refresh) powered by `djangorestframework-simplejwt`.

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| **Framework** | [Django 5.2+ / 6.0+](https://www.djangoproject.com/) |
| **REST API** | [Django REST Framework 3.16+](https://www.django-rest-framework.org/) |
| **Authentication** | [SimpleJWT (JSON Web Tokens)](https://django-rest-framework-simplejwt.readthedocs.io/) |
| **Database** | [PostgreSQL](https://www.postgresql.org/) via [`psycopg3`](https://www.psycopg.org/psycopg3/) & `dj-database-url` |
| **Email Service** | [Resend](https://resend.com/) via [`django-anymail`](https://anymail.dev/) |
| **File Storage** | [AWS S3](https://aws.amazon.com/s3/) via `django-storages` and `boto3` / Local Storage |
| **API Documentation** | [drf-spectacular](https://drf-spectacular.readthedocs.io/) (OpenAPI / Swagger / ReDoc) |
| **Static Files & WSGI** | [WhiteNoise](http://whitenoise.evans.io/) & [Gunicorn](https://gunicorn.org/) |

---

## 🔐 RBAC & Data Scoping Architecture

### Default System Roles

| Role | Data Scope | Key Capabilities |
|---|---|---|
| **`ADMIN`** | `GLOBAL` | Full system access across all institutions, manage institutions, roles, leave types, employees, and approve/reject all leaves. |
| **`DIRECTOR`** | `GLOBAL` | Global view of leaves, approvals, reports, and employee oversight across all branches. |
| **`HR`** | `INSTITUTION` | Manage branch employees, view branch leaves, approve/reject branch leaves, download documents, and view branch reports. |
| **`MANAGER`** | `INSTITUTION` | View branch employees and leaves, approve/reject branch leaves, download documents, and view branch reports. |
| **`STAFF`** | `OWN` | Submit leave requests, cancel own pending leaves, view personal leave balances and notifications. |

### Available Action Permissions

- `employee.view`, `employee.create`, `employee.edit`, `employee.delete`
- `leave.create`, `leave.cancel_own`, `leave.cancel_any`, `leave.approve`, `leave.reject`, `leave.download_document_any`
- `leave_type.manage`, `institution.manage`, `role.manage`, `report.view`

---

## 🏢 Branch-Specific & Allowed Leave Types

1. **System Templates vs. Custom Branch Types**:
   - `LeaveType.institution = None`: System-wide default templates available across all branches (e.g. *Annual Leave*, *Sick Leave*, *Family Responsibility Leave*).
   - `LeaveType.institution = <Institution>`: Custom leave types created specifically for a single branch.
2. **Allowed Leave Types per Branch**:
   - `Institution.allowed_leave_types`: A Many-to-Many relationship on `Institution` designating exactly which leave types employees in that branch can select.
3. **Automatic View Filtering**:
   - **`GET /api/leave-types/`**: Automatically returns only the allowed leave types for the authenticated employee's branch.
   - **`GET /api/leaves/my-summary/`**: Dashboard summary cards and balances strictly render for the employee's branch-allowed types.
   - **`POST /api/leaves/`**: Submissions for disallowed leave types are rejected on validation.
   - **`GET /api/institutions/`**: Accessible to all authenticated users, exposing `allowed_leave_types` and `allowed_leave_type_names` to populate the frontend Active Branches table and configuration modals.

---

## 📦 Prerequisites

- **Python**: `>= 3.12`
- **PostgreSQL**: `>= 14`
- **Package Manager**: [`uv`](https://github.com/astral-sh/uv) (recommended) or `pip`

---

## 🚀 Installation & Setup

### 1. Clone Repository
```bash
git clone https://github.com/joyministries/Leave_System_Backend.git
cd Leave_System_Backend
```

### 2. Set Up Virtual Environment

Using `uv`:
```bash
uv venv
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

uv pip sync pyproject.toml
```

Or using standard `pip`:
```bash
python -m venv .venv
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

---

## ⚙️ Environment Configuration

Create a `.env` file in the project root:

```env
# Django Core Settings
DEBUG=True
SECRET_KEY=your-super-secret-django-key
ALLOWED_HOSTS=localhost,127.0.0.1,.onrender.com

# Database Connection (MariaDB/MySQL)
DATABASE_URL=mysql://joyministries_leavesadmin:your-password@joyministries.co.za:3306/joyministries_leaves

# Frontend URLs (for password reset and activation links)
FRONTEND_URL=http://localhost:5173
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

# Email Settings (Resend via Anymail)
EMAIL_BACKEND=anymail.backends.resend.EmailBackend
RESEND_API_KEY=re_your_resend_api_key
DEFAULT_FROM_EMAIL=Leave System <notifications@yourdomain.com>
LEAVE_NOTIFICATION_EMAIL=admin@yourdomain.com

# AWS S3 Storage (Optional - falls back to local storage if disabled)
USE_S3=False
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_STORAGE_BUCKET_NAME=your-bucket-name
AWS_S3_REGION_NAME=af-south-1

# Initial Administrator Seed Credentials
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=InitialAdminSecurePassword123!
```

---

## 🗄️ Database Initialization & Seeding

Run the following sequence to prepare your database:

```bash
# 1. Apply all database migrations
python manage.py migrate

# 2. Seed default permissions and system roles (STAFF, MANAGER, HR, DIRECTOR, ADMIN)
python manage.py seed_rbac

# 3. Create default institution, standard leave types, and the superuser
python manage.py setup_admin
```

---

## 🏃 Running the Application

### Development Server
```bash
python manage.py runserver
```
The API will be accessible at: `http://127.0.0.1:8000/api/`

### Production Server (Gunicorn)
```bash
gunicorn leavesystem.wsgi:application --bind 0.0.0.0:8000 --workers 4
```

---

## 📁 Project Structure

```
backendproject/
├── leaves/                       # Main core application
│   ├── management/commands/      # Custom management scripts (seed_rbac, setup_admin)
│   ├── migrations/               # Database migrations (RBAC, Multi-branch, Leave types)
│   ├── templates/emails/         # HTML transactional email templates
│   ├── admin.py                  # Django admin registrations
│   ├── exceptions.py             # Custom DRF exception handlers
│   ├── filters.py                # RoleBasedAccessFilter (data scoping)
│   ├── models.py                 # Core models (Employee, Role, Leave, Institution, etc.)
│   ├── permissions.py            # HasAction, HasAnyAction, InInstitutionScope
│   ├── serializers.py            # DRF ModelSerializers & custom field handlers
│   ├── signals.py                # Post-save signals (leave balances, user activation)
│   ├── urls.py                   # App URL route configuration
│   ├── utils.py                  # Leave calculation, token generation, email senders
│   └── views.py                  # ModelViewSets & APIViews
├── leavesystem/                  # Project configuration directory
│   ├── asgi.py
│   ├── settings.py               # Django settings (JWT, CORS, Storage, Email, DB)
│   ├── urls.py                   # Root URL router
│   └── wsgi.py
├── API_ENDPOINTS.md              # Detailed API endpoint reference
├── manage.py
├── pyproject.toml
└── requirements.txt
```

---

## 📡 API Overview

Full endpoint documentation is available in [API_ENDPOINTS.md](file:///c:/Users/MJ/Documents/backendproject/API_ENDPOINTS.md) and interactive Swagger/OpenAPI docs at `/api/docs/`.

### Core Endpoints

| Method | Endpoint | Description | Access |
|---|---|---|---|
| `POST` | `/api/auth/login/` | User login (returns access, refresh, employee profile) | Public |
| `POST` | `/api/auth/logout/` | Blacklist refresh token | Authenticated |
| `POST` | `/api/auth/set-password/` | Set password via email invite/reset token | Public |
| `GET` | `/api/auth/me/` | Get current user's profile and permissions | Authenticated |
| `GET` / `POST` | `/api/leaves/` | List scoped leaves / Submit new leave application | Authenticated |
| `GET` | `/api/leaves/my-summary/` | Employee dashboard leave summary cards & balances | Authenticated |
| `GET` | `/api/leaves/monthly-report/` | Monthly summary metrics & employee breakdown | `report.view` |
| `POST` | `/api/leaves/{id}/update_status/` | Approve or reject a leave request | `leave.approve` / `leave.reject` |
| `POST` | `/api/leaves/{id}/cancel/` | Employee cancels own pending leave | Authenticated |
| `GET` | `/api/leaves/{id}/download_document/` | Download attached supporting document | Owner / `leave.download_document_any` |
| `GET` / `POST` | `/api/employees/` | List / Onboard new employee (sends invite) | `employee.view` / `employee.create` |
| `GET` | `/api/institutions/` | List active branches and their allowed leave types | Authenticated |
| `POST` / `PATCH` / `DELETE` | `/api/institutions/{id}/` | Create / Update allowed leave types / Delete branch | `institution.manage` |
| `GET` | `/api/leave-types/` | List branch-allowed active leave types | Authenticated |
| `POST` / `PATCH` / `DELETE` | `/api/leave-types/{id}/` | Create / Edit / Delete leave types | `leave_type.manage` |
| `GET` / `POST` | `/api/roles/` | List system templates & custom institution roles | `role.manage` |
| `GET` | `/api/notifications/` | View user notifications | Authenticated |
| `GET` | `/api/notifications/unread_count/` | Get unread notification badge count | Authenticated |

---

## 🔧 Management Commands

- **`python manage.py seed_rbac`**:
  Seeds and synchronizes all `Permission` records and assigns default action codes to `STAFF`, `MANAGER`, `HR`, `DIRECTOR`, and `ADMIN`. Can be run safely anytime to sync new permissions.
- **`python manage.py setup_admin`**:
  Idempotently creates the default institution (*Team Impact Christian University*), initializes default leave types (Annual, Sick, Study, etc.), and sets up the root superuser.

---

## 🧪 Testing

Run the automated test suite with:

```bash
python manage.py test leaves
```

---

## 📄 License

Proprietary — All rights reserved by Joy Ministries / Team Impact Christian University.
