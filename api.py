# main.py - FastAPI Authentication API
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import asyncpg
import os
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Machine Authentication API", version="1.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for your specific domains in production
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Pydantic models
class AuthRequest(BaseModel):
    machineId: str
    key: Optional[str] = None

class AuthResponse(BaseModel):
    success: bool
    message: str
    received: dict

class ErrorResponse(BaseModel):
    success: bool
    message: str
    received: dict
    error: Optional[str] = None

# Database connection pool
db_pool = None

@app.on_event("startup")
async def startup():
    global db_pool
    database_url = os.getenv("DATABASE_URL")
    
    if not database_url:
        logger.error("DATABASE_URL environment variable is not set.")
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    
    try:
        db_pool = await asyncpg.create_pool(
            database_url,
            ssl='require' if 'postgres://' in database_url else None,
            min_size=1,
            max_size=10
        )
        logger.info("Database connection pool created successfully")
    except Exception as e:
        logger.error(f"Failed to create database pool: {e}")
        raise

@app.on_event("shutdown")
async def shutdown():
    global db_pool
    if db_pool:
        await db_pool.close()
        logger.info("Database connection pool closed")

@app.get("/")
async def root():
    return {"message": "Machine Authentication API", "version": "1.0.0"}

@app.post("/auth", response_model=AuthResponse)
async def authenticate(auth_request: AuthRequest, request: Request):
    """
    Authenticate machine with optional key activation.
    
    Flow 1 (Auto-login): Only machineId provided - check if machine is already registered
    Flow 2 (Activation): machineId + key provided - activate new key or validate existing
    """
    
    # Log the received request
    request_body = auth_request.dict()
    logger.info(f"Received request body: {request_body}")
    
    # Validate machineId is provided
    if not auth_request.machineId:
        logger.info("Missing machineId in request.")
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "message": "Machine ID is required. Please provide a valid machineId.",
                "received": request_body
            }
        )
    
    # Check database connection
    if not db_pool:
        logger.error("Database connection not available.")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Server configuration error.",
                "received": request_body
            }
        )
    
    try:
        async with db_pool.acquire() as connection:
            
            # FLOW 1: AUTO-LOGIN (No key provided)
            if not auth_request.key:
                logger.info(f"Auto-login attempt for Machine ID: {auth_request.machineId}")
                
                query = "SELECT expires_at FROM user_keys WHERE machine_id = $1"
                rows = await connection.fetch(query, auth_request.machineId)
                
                if not rows:
                    logger.info(f"Machine ID {auth_request.machineId} not found for auto-login.")
                    raise HTTPException(
                        status_code=404,
                        detail={
                            "success": False,
                            "message": "Machine not registered. Please activate.",
                            "received": request_body
                        }
                    )
                
                license_record = rows[0]
                expiration_date = license_record['expires_at']
                current_time = datetime.now()
                
                if expiration_date < current_time:
                    logger.info(f"License for Machine ID {auth_request.machineId} has expired.")
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "success": False,
                            "message": "Your license has expired.",
                            "received": request_body
                        }
                    )
                
                logger.info(f"Successful auto-login for Machine ID: {auth_request.machineId}")
                return AuthResponse(
                    success=True,
                    message="Welcome back! Login successful.",
                    received=request_body
                )
            
            # FLOW 2: ACTIVATION / VALIDATION (Key is provided)
            if auth_request.key:
                logger.info(f"Activation attempt with key on Machine ID: {auth_request.machineId}")
                
                query = "SELECT id, expires_at, machine_id FROM user_keys WHERE key_value = $1"
                rows = await connection.fetch(query, auth_request.key)
                
                if not rows:
                    raise HTTPException(
                        status_code=404,
                        detail={
                            "success": False,
                            "message": "Invalid key.",
                            "received": request_body
                        }
                    )
                
                license_record = rows[0]
                expiration_date = license_record['expires_at']
                current_time = datetime.now()
                
                if expiration_date < current_time:
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "success": False,
                            "message": "This key has expired.",
                            "received": request_body
                        }
                    )
                
                # Key already associated with this machine
                if license_record['machine_id'] and license_record['machine_id'] == auth_request.machineId:
                    return AuthResponse(
                        success=True,
                        message="Login successful.",
                        received=request_body
                    )
                
                # Key already associated with different machine
                if license_record['machine_id'] and license_record['machine_id'] != auth_request.machineId:
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "success": False,
                            "message": "Key is already in use by another machine.",
                            "received": request_body
                        }
                    )
                
                # Associate the key with the machineId (first time activation)
                if not license_record['machine_id']:
                    update_query = "UPDATE user_keys SET machine_id = $1 WHERE key_value = $2"
                    await connection.execute(update_query, auth_request.machineId, auth_request.key)
                    logger.info(f"Key {auth_request.key} has been activated for Machine ID: {auth_request.machineId}")
                    
                    return AuthResponse(
                        success=True,
                        message="Key successfully activated. Login successful.",
                        received=request_body
                    )
    
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as db_error:
        logger.error(f"Database Error: {str(db_error)}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Internal Server Error.",
                "received": request_body,
                "error": str(db_error)
            }
        )

# Additional endpoints for management
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        if db_pool:
            async with db_pool.acquire() as connection:
                await connection.fetchval("SELECT 1")
            return {"status": "healthy", "database": "connected"}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=503,
            detail={"status": "unhealthy", "database": "disconnected", "error": str(e)}
        )

@app.get("/machines/{machine_id}/status")
async def get_machine_status(machine_id: str):
    """Get the status of a specific machine"""
    if not db_pool:
        raise HTTPException(status_code=500, detail="Database connection not available")
    
    try:
        async with db_pool.acquire() as connection:
            query = "SELECT machine_id, expires_at, key_value FROM user_keys WHERE machine_id = $1"
            rows = await connection.fetch(query, machine_id)
            
            if not rows:
                raise HTTPException(
                    status_code=404,
                    detail={"message": "Machine not found"}
                )
            
            license_record = rows[0]
            current_time = datetime.now()
            is_expired = license_record['expires_at'] < current_time
            
            return {
                "machine_id": license_record['machine_id'],
                "expires_at": license_record['expires_at'].isoformat(),
                "is_expired": is_expired,
                "status": "expired" if is_expired else "active"
            }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting machine status: {e}")
        raise HTTPException(status_code=500, detail={"error": str(e)})

# Run with: uvicorn main:app --reload --host 0.0.0.0 --port 8000
