
from fastapi import FastAPI, Request, Query, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import jwt
from typing import Optional

load_dotenv()

app = FastAPI()

security = HTTPBearer()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

SECRET_KEY = os.getenv("JWT_SECRET")
if not SECRET_KEY:
    raise ValueError(" JWT_SECRET environment variable is required!")

ALLOWED_ORIGINS = os.getenv("FRONTEND_URL", "http://localhost:5173").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    max_age=3600,
)


from collections import defaultdict
from time import time

request_counts = defaultdict(list)

def rate_limit_check(ip: str, limit: int = 100, window: int = 60):
    """Simple rate limiting: max `limit` requests per `window` seconds"""
    now = time()
    request_counts[ip] = [req_time for req_time in request_counts[ip] if now - req_time < window]
    
    if len(request_counts[ip]) >= limit:
        raise HTTPException(status_code=429, detail="Too many requests. Please try again later.")
    
    request_counts[ip].append(now)

def safe_float(value):
    if not value:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None

def safe_int(value):
    if not value:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None
    

DEMO_USERS = {
    "user1": {"user_id": 1, "username": "user1", "role": "data_entry"},
    "user2": {"user_id": 2, "username": "user2", "role": "update"},
    "user3": {"user_id": 3, "username": "user3", "role": "viewer"},
}

def get_db_connection():
    try:
        conn = psycopg2.connect(
            os.getenv("DATABASE_URL"),
            cursor_factory=RealDictCursor,
            sslmode='require',
            connect_timeout=10
        )
        return conn
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(e)}")


def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Project_Master (
        Project_Number INTEGER PRIMARY KEY,
        Project_Name TEXT NOT NULL,
        Outlet_Code TEXT,
        Location TEXT,
        Start_Date DATE,
        End_Date DATE,
        Manager TEXT,
        Status TEXT,
        Project_Type TEXT,
        Business_Vertical TEXT,
        Region TEXT,
        Budgeted_INR NUMERIC(15, 2),
        Last_Update DATE,
        Project_Stage TEXT,
        Risk_Level TEXT,
        Remarks TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Project_Milestones (
        Milestone_ID SERIAL PRIMARY KEY,
        Project_Code INTEGER NOT NULL,
        Milestone TEXT NOT NULL,
        Planned_Date DATE,
        Actual_Date DATE,
        Status TEXT,
        Responsible TEXT,
        Delay_Days INTEGER DEFAULT 0,
        Cost_Impact_Lakh NUMERIC(15, 2),
        Cost_Per_Day_Lakh NUMERIC(15, 2),
        Revenue_Delay_Days INTEGER,
        Dynamic_Planned_Completion_Date DATE,
        Comments TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (Project_Code) REFERENCES Project_Master(Project_Number) ON DELETE CASCADE
    )
    """)

    # Create index for faster queries
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_project_status ON Project_Master(Status);
    """)
    
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_milestone_project ON Project_Milestones(Project_Code);
    """)

    conn.commit()
    cursor.close()
    conn.close()

create_tables()

# Authentication functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token and return user data"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        
        if username is None or username not in DEMO_USERS:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid authentication credentials"
            )
        
        user_data = DEMO_USERS[username].copy()
        return user_data
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please login again."
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials"
        )

# Input validation helper
def validate_project_number(project_num):
    """Validate project number is positive integer"""
    try:
        num = int(project_num)
        if num <= 0:
            raise ValueError("Project number must be positive")
        return num
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid project number")

# Auth endpoint (public - no token required)
@app.post("/api/auth/login")
async def login(request: Request):
    """
    Simple login - just provide username (user1, user2, or user3)
    Returns JWT token for subsequent requests
    """
    try:
        data = await request.json()
        username = data.get("username", "").strip()
        
        # Rate limiting
        client_ip = request.client.host
        rate_limit_check(client_ip, limit=10, window=60)  # 10 login attempts per minute
        
        if username not in DEMO_USERS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username. Use: user1, user2, or user3"
            )
        
        user_data = DEMO_USERS[username]
        
        # Create token
        token = create_access_token({
            "user_id": user_data['user_id'],
            "username": user_data['username'],
            "role": user_data['role']
        })

        return {
            "status": "success",
            "token": token,
            "user": {
                "username": user_data['username'],
                "role": user_data['role']
            }
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.post("/submit-form")
async def add_project(request: Request, current_user: dict = Depends(verify_token)):
    try:
        data = await request.json()
        
        if not data.get("projectNumber") or not data.get("projectName"):
            raise HTTPException(status_code=400, detail="Project number and name are required")
        
        project_num = validate_project_number(data["projectNumber"])
        
        conn = get_db_connection()
        cursor = conn.cursor()

        # REMOVED 'created_by' from columns and removed one %s
        cursor.execute("""
            INSERT INTO Project_Master (
                Project_Number, Project_Name, Outlet_Code, Location,
                Start_Date, End_Date, Manager, Status, Project_Type,
                Business_Vertical, Region, Budgeted_INR, Last_Update,
                Project_Stage, Risk_Level, Remarks
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (Project_Number) 
            DO UPDATE SET
                Project_Name = EXCLUDED.Project_Name,
                Outlet_Code = EXCLUDED.Outlet_Code,
                Location = EXCLUDED.Location,
                Start_Date = EXCLUDED.Start_Date,
                End_Date = EXCLUDED.End_Date,
                Manager = EXCLUDED.Manager,
                Status = EXCLUDED.Status,
                Project_Type = EXCLUDED.Project_Type,
                Business_Vertical = EXCLUDED.Business_Vertical,
                Region = EXCLUDED.Region,
                Budgeted_INR = EXCLUDED.Budgeted_INR,
                Last_Update = EXCLUDED.Last_Update,
                Project_Stage = EXCLUDED.Project_Stage,
                Risk_Level = EXCLUDED.Risk_Level,
                Remarks = EXCLUDED.Remarks
        """, (
            project_num,
            data["projectName"][:255],
            data.get("outletCode", "")[:100],
            data.get("location", "")[:255],
            parse_date(data.get("startDate")),
            parse_date(data.get("endDate")),
            data.get("manager", "")[:100],
            data.get("status", "")[:50],
            data.get("projectType", "")[:100],
            data.get("businessVertical", "")[:100],
            data.get("region", "")[:100],
            safe_float(data.get("budgetedINR")), # Changed to safe_float
            parse_date(data.get("lastUpdate")),
            data.get("projectStage", "")[:100],
            data.get("riskLevel", "")[:50],
            data.get("remarks", "")[:1000]
        ))

        conn.commit()
        cursor.close()
        conn.close()
        return {"status": "success", "message": "Project added successfully!"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error adding project: {str(e)}")



@app.post("/update-form")
async def update_form(request: Request, current_user: dict = Depends(verify_token)):
    try:
        data = await request.json()
        
        if not data.get("projectCode") or not data.get("milestone"):
            raise HTTPException(status_code=400, detail="Project code and milestone are required")
        
        project_code = validate_project_number(data["projectCode"])
        
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify project exists
        cursor.execute("SELECT Project_Number FROM Project_Master WHERE Project_Number = %s", (project_code,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Project not found")

        # Calculate delay
        delay_days = 0
        planned = data.get("plannedDate")
        actual = data.get("actualDate")

        if planned and actual:
            try:
                planned_dt = datetime.strptime(planned, "%Y-%m-%d")
                actual_dt = datetime.strptime(actual, "%Y-%m-%d")
                delay_days = max(0, (actual_dt - planned_dt).days)
            except Exception:
                delay_days = 0

        # Calculate cost impact
        cost_day_val = safe_float(data.get("costDay"))
        cost_impact = 0.0
        if delay_days > 0 and cost_day_val:
            cost_impact = delay_days * cost_day_val

        # REMOVED 'created_by' from INSERT columns and removed one %s
        cursor.execute("""
            INSERT INTO Project_Milestones (
                Project_Code, Milestone, Planned_Date, Actual_Date,
                Status, Responsible, Delay_Days, Cost_Impact_Lakh,
                Cost_Per_Day_Lakh, Revenue_Delay_Days,
                Dynamic_Planned_Completion_Date, Comments
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            project_code,
            data["milestone"][:255],
            data.get("plannedDate") if data.get("plannedDate") else None,
            data.get("actualDate") if data.get("actualDate") else None,
            data.get("status", "")[:50],
            data.get("responsible", "")[:100],
            delay_days,
            cost_impact,
            cost_day_val, # Used safe variable
            safe_int(data.get("revenueDelay")), # Used safe_int
            data.get("dynamicPlannedCompletionDate") if data.get("dynamicPlannedCompletionDate") else None,
            data.get("comments", "")[:1000]
        ))

        conn.commit()
        cursor.close()
        conn.close()

        return {"status": "success", "message": "Milestone added successfully!"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error adding milestone: {str(e)}")

@app.get("/get-total-projects")
async def get_total_projects(current_user: dict = Depends(verify_token)):
    """Return total number of projects - requires authentication"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM Project_Master")
        result = cursor.fetchone()
        total_projects = result['count']
        cursor.close()
        conn.close()
        return {"status": "success", "total_projects": total_projects}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/get-data")
async def get_data(
    project_code: int = Query(..., alias="project_code"),
    current_user: dict = Depends(verify_token)
):
    """Get detailed data for a specific project - requires authentication"""
    try:
        project_code = validate_project_number(project_code)
        
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT Project_Name FROM Project_Master WHERE Project_Number = %s",
            (project_code,)
        )
        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Project not found")
        project_name = result['project_name']

        cursor.execute(
            "SELECT COUNT(*) as count FROM Project_Milestones WHERE Project_Code = %s",
            (project_code,)
        )
        milestones_total = cursor.fetchone()['count']

        cursor.execute(
            "SELECT COUNT(*) as count FROM Project_Milestones WHERE Project_Code = %s AND Status = 'Completed'",
            (project_code,)
        )
        completed = cursor.fetchone()['count']

        cursor.execute(
            "SELECT COUNT(*) as count FROM Project_Milestones WHERE Project_Code = %s AND Status = 'Pending'",
            (project_code,)
        )
        pending = cursor.fetchone()['count']

        cursor.execute(
            "SELECT COUNT(*) as count FROM Project_Milestones WHERE Project_Code = %s AND Delay_Days > 0",
            (project_code,)
        )
        delayed = cursor.fetchone()['count']

        cursor.execute(
            "SELECT COALESCE(SUM(Cost_Impact_Lakh), 0) as total FROM Project_Milestones WHERE Project_Code = %s",
            (project_code,)
        )
        total_cost_impact = cursor.fetchone()['total']

        cursor.execute("""
            SELECT Revenue_Delay_Days FROM Project_Milestones
            WHERE Project_Code = %s AND Milestone = 'Commercial Opening'
            LIMIT 1
        """, (project_code,))
        row = cursor.fetchone()
        revenue_delay = row['revenue_delay_days'] if row and row['revenue_delay_days'] else 0

        percent_milestones = 0
        if milestones_total > 0:
            percent_milestones = round((completed / milestones_total) * 100, 2)

        cursor.execute("""
            SELECT Milestone, Planned_Date, Actual_Date
            FROM Project_Milestones
            WHERE Project_Code = %s AND Planned_Date IS NOT NULL AND Actual_Date IS NOT NULL
        """, (project_code,))
        milestones_chart = cursor.fetchall()

        cursor.close()
        conn.close()

        chart_data = [
            {
                "milestone": row['milestone'],
                "planned": str(row['planned_date']),
                "actual": str(row['actual_date'])
            }
            for row in milestones_chart
        ]

        data = {
            "Project Code": project_code,
            "Project Name": project_name,
            "Milestones Total": milestones_total,
            "Completed": completed,
            "Delayed": delayed,
            "Pending": pending,
            "Total Cost Impact (₹ Lakh)": float(total_cost_impact),
            "Revenue Delay (Days)": revenue_delay,
            "% Milestones Complete": f"{percent_milestones}%",
            "Milestone Chart": chart_data
        }

        return {"status": "success", "data": data}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/get-all-projects")
async def get_all_projects(current_user: dict = Depends(verify_token)):
    """Get all projects with summary - requires authentication"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM Project_Master ORDER BY Project_Number ASC")
        projects = cursor.fetchall()

        projects_list = []
        total_projects = 0
        completed_projects = 0
        pending_projects = 0
        active_projects = 0

        for p in projects:
            total_projects += 1
            status_val = (p.get("status") or "").strip().lower()

            if status_val == "completed":
                completed_projects += 1
            elif status_val == "active":
                active_projects += 1
            elif status_val in ("pending", "planned"):
                pending_projects += 1

            projects_list.append({
                "projectNumber": p.get("project_number"),
                "projectName": p.get("project_name"),
                "status": p.get("status"),
                "manager": p.get("manager"),
                "startDate": str(p.get("start_date")) if p.get("start_date") else None,
                "endDate": str(p.get("end_date")) if p.get("end_date") else None,
                "budgetedINR": float(p.get("budgeted_inr")) if p.get("budgeted_inr") else None,
                "projectStage": p.get("project_stage"),
                "riskLevel": p.get("risk_level"),
                "remarks": p.get("remarks"),
            })

        cursor.close()
        conn.close()

        summary = {
            "totalProjects": total_projects,
            "completedProjects": completed_projects,
            "pendingProjects": pending_projects,
            "activeProjects": active_projects
        }

        return {"status": "success", "summary": summary, "projects": projects_list}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/get-project-history")
async def get_project_history(
    project_code: int = Query(..., alias="project_code"),
    current_user: dict = Depends(verify_token)
):
    """Get full milestone history - requires authentication"""
    try:
        project_code = validate_project_number(project_code)
        
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM Project_Master WHERE Project_Number = %s", (project_code,))
        proj = cursor.fetchone()
        if not proj:
            raise HTTPException(status_code=404, detail="Project not found")

        cursor.execute("""
            SELECT * FROM Project_Milestones
            WHERE Project_Code = %s
            ORDER BY Planned_Date NULLS LAST, Milestone_ID ASC
        """, (project_code,))
        milestones = cursor.fetchall()

        cursor.close()
        conn.close()

        return {
            "status": "success",
            "milestones": [dict(m) for m in milestones],
            "project": {
                "projectNumber": proj["project_number"],
                "projectName": proj["project_name"]
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Public health check (no authentication)
@app.get("/health")
async def health_check():
    """Health check endpoint - public"""
    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat()
    }



def parse_date(date_str):
    if not date_str:
        return None
    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y"):
        try:
            return datetime.strptime(date_str, fmt).date()
        except ValueError:
            continue
    return None