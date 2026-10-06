import sqlite3
import os
from datetime import datetime
import uuid
import hashlib
import re
import getpass
from typing import Optional, Dict, Any, List

# ======================================================
# DATABASE CLASS WITH SQLITE
# ======================================================
class Database:
    def __init__(self, db_name="insurance.db"):
        self.db_name = db_name
        self.conn = None
        self.cursor = None
        self.connect()
        self.create_tables()
    
    def connect(self):
        """Create database connection"""
        self.conn = sqlite3.connect(self.db_name)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
    
    def create_tables(self):
        """Create all necessary tables if they don't exist"""
        # Admins table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                email TEXT,
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        ''')
        
        # Customers table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT,
                address TEXT,
                created_at TEXT NOT NULL,
                last_login TEXT,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        # Policies table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_id TEXT UNIQUE NOT NULL,
                customer_id INTEGER NOT NULL,
                customer_username TEXT NOT NULL,
                policy_type TEXT NOT NULL,
                coverage_amount REAL NOT NULL,
                premium REAL NOT NULL,
                start_date TEXT NOT NULL,
                end_date TEXT NOT NULL,
                status TEXT DEFAULT 'Active',
                created_at TEXT NOT NULL,
                FOREIGN KEY (customer_id) REFERENCES customers(id)
            )
        ''')
        
        # Claims table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS claims (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                claim_id TEXT UNIQUE NOT NULL,
                customer_id INTEGER NOT NULL,
                customer_username TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                claim_amount REAL NOT NULL,
                reason TEXT,
                date_filed TEXT NOT NULL,
                status TEXT DEFAULT 'Pending',
                processed_by INTEGER,
                processed_date TEXT,
                rejection_reason TEXT,
                FOREIGN KEY (customer_id) REFERENCES customers(id),
                FOREIGN KEY (processed_by) REFERENCES admins(id)
            )
        ''')
        
        # Queries table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_id TEXT UNIQUE NOT NULL,
                customer_id INTEGER NOT NULL,
                customer_username TEXT NOT NULL,
                message TEXT NOT NULL,
                date_submitted TEXT NOT NULL,
                status TEXT DEFAULT 'Pending',
                resolved_by INTEGER,
                resolved_by_name TEXT,
                resolved_date TEXT,
                response TEXT,
                FOREIGN KEY (customer_id) REFERENCES customers(id),
                FOREIGN KEY (resolved_by) REFERENCES admins(id)
            )
        ''')
        
        # Payments table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payment_id TEXT UNIQUE NOT NULL,
                customer_id INTEGER NOT NULL,
                customer_username TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                amount REAL NOT NULL,
                payment_method TEXT,
                payment_date TEXT NOT NULL,
                status TEXT DEFAULT 'Completed',
                transaction_id TEXT,
                FOREIGN KEY (customer_id) REFERENCES customers(id)
            )
        ''')
        
        # Audit log table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user TEXT NOT NULL,
                user_type TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT
            )
        ''')
        
        # Create indexes for better performance
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_policies_customer ON policies(customer_id)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_claims_customer ON claims(customer_id)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_payments_customer ON payments(customer_id)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_queries_customer ON queries(customer_id)')
        
        # Insert default admin if not exists
        self.cursor.execute("SELECT COUNT(*) FROM admins")
        if self.cursor.fetchone()[0] == 0:
            default_password = os.environ.get('ADMIN_PASSWORD', 'Admin@123')
            hashed_password = self._hash_password(default_password)
            self.cursor.execute('''
                INSERT INTO admins (username, password, name, email, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', ('admin', hashed_password, 'System Admin', 'admin@insurance.com', 
                  datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            self.conn.commit()
            print("⚠️ Default admin created. Please change password immediately!")
        
        self.conn.commit()
    
    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def _validate_phone(self, phone: str) -> bool:
        """Validate phone number"""
        pattern = r'^\+?1?\d{9,15}$'
        return re.match(pattern, phone) is not None
    
    def _get_customer_id(self, username: str) -> Optional[int]:
        """Get customer ID by username"""
        self.cursor.execute("SELECT id FROM customers WHERE username = ?", (username,))
        result = self.cursor.fetchone()
        return result[0] if result else None
    
    # ============ ADMIN OPERATIONS ============
    def verify_admin(self, username: str, password: str) -> Optional[Dict]:
        """Verify admin credentials"""
        hashed_password = self._hash_password(password)
        self.cursor.execute('''
            SELECT * FROM admins WHERE username = ? AND password = ?
        ''', (username, hashed_password))
        result = self.cursor.fetchone()
        
        if result:
            # Update last login
            self.cursor.execute('''
                UPDATE admins SET last_login = ? WHERE id = ?
            ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), result['id']))
            self.conn.commit()
            return dict(result)
        return None
    
    def get_admin_by_id(self, admin_id: int) -> Optional[Dict]:
        """Get admin by ID"""
        self.cursor.execute("SELECT * FROM admins WHERE id = ?", (admin_id,))
        result = self.cursor.fetchone()
        return dict(result) if result else None
    
    # ============ CUSTOMER OPERATIONS ============
    def verify_customer(self, username: str, password: str) -> Optional[Dict]:
        """Verify customer credentials"""
        hashed_password = self._hash_password(password)
        self.cursor.execute('''
            SELECT * FROM customers WHERE username = ? AND password = ? AND is_active = 1
        ''', (username, hashed_password))
        result = self.cursor.fetchone()
        
        if result:
            # Update last login
            self.cursor.execute('''
                UPDATE customers SET last_login = ? WHERE id = ?
            ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), result['id']))
            self.conn.commit()
            return dict(result)
        return None
    
    def add_customer(self, data: Dict) -> int:
        """Add new customer"""
        # Hash password
        if "password" in data:
            data["password"] = self._hash_password(data["password"])
        
        # Validate required fields
        required_fields = ["username", "password", "name", "email"]
        if not all(k in data for k in required_fields):
            raise ValueError("Missing required fields")
        
        # Validate email
        if not self._validate_email(data.get("email", "")):
            raise ValueError("Invalid email format")
        
        # Validate phone if provided
        if data.get("phone") and not self._validate_phone(data["phone"]):
            raise ValueError("Invalid phone number format")
        
        # Check for duplicate username
        self.cursor.execute("SELECT id FROM customers WHERE username = ?", (data["username"],))
        if self.cursor.fetchone():
            raise ValueError("Username already exists")
        
        # Insert customer
        self.cursor.execute('''
            INSERT INTO customers (username, password, name, email, phone, address, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            data["username"],
            data["password"],
            data["name"],
            data["email"],
            data.get("phone", ""),
            data.get("address", ""),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        self.conn.commit()
        return self.cursor.lastrowid
    
    def update_customer(self, username: str, updated_data: Dict) -> bool:
        """Update customer information"""
        # If password is being updated, hash it
        if "password" in updated_data:
            updated_data["password"] = self._hash_password(updated_data["password"])
        
        # Validate email if being updated
        if "email" in updated_data and not self._validate_email(updated_data["email"]):
            raise ValueError("Invalid email format")
        
        # Validate phone if being updated
        if "phone" in updated_data and not self._validate_phone(updated_data["phone"]):
            raise ValueError("Invalid phone number format")
        
        # Build update query
        set_clause = []
        values = []
        for key, value in updated_data.items():
            set_clause.append(f"{key} = ?")
            values.append(value)
        
        values.append(username)
        query = f"UPDATE customers SET {', '.join(set_clause)} WHERE username = ?"
        
        self.cursor.execute(query, values)
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    def change_password(self, username: str, current_password: str, new_password: str) -> bool:
        """Change customer password"""
        # Verify current password
        hashed_current = self._hash_password(current_password)
        self.cursor.execute(
            "SELECT id FROM customers WHERE username = ? AND password = ?",
            (username, hashed_current)
        )
        if not self.cursor.fetchone():
            return False
        
        # Update to new password
        hashed_new = self._hash_password(new_password)
        self.cursor.execute(
            "UPDATE customers SET password = ? WHERE username = ?",
            (hashed_new, username)
        )
        self.conn.commit()
        return True
    
    def get_all_customers(self) -> List[Dict]:
        """Get all customers"""
        self.cursor.execute('''
            SELECT id, username, name, email, phone, address, created_at, last_login, is_active
            FROM customers ORDER BY created_at DESC
        ''')
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_customer_by_username(self, username: str) -> Optional[Dict]:
        """Get customer by username"""
        self.cursor.execute('''
            SELECT * FROM customers WHERE username = ?
        ''', (username,))
        result = self.cursor.fetchone()
        return dict(result) if result else None
    
    def get_customer_by_id(self, customer_id: int) -> Optional[Dict]:
        """Get customer by ID"""
        self.cursor.execute("SELECT * FROM customers WHERE id = ?", (customer_id,))
        result = self.cursor.fetchone()
        return dict(result) if result else None
    
    def deactivate_customer(self, username: str) -> bool:
        """Deactivate a customer account"""
        self.cursor.execute('''
            UPDATE customers SET is_active = 0 WHERE username = ?
        ''', (username,))
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    # ============ POLICY OPERATIONS ============
    def add_policy(self, data: Dict) -> int:
        """Add new policy"""
        # Get customer_id
        customer_id = self._get_customer_id(data["customer_username"])
        if not customer_id:
            raise ValueError("Customer not found")
        
        # Generate policy_id if not provided
        if "policy_id" not in data:
            data["policy_id"] = str(uuid.uuid4())[:8]
        
        self.cursor.execute('''
            INSERT INTO policies (
                policy_id, customer_id, customer_username, policy_type, 
                coverage_amount, premium, start_date, end_date, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data["policy_id"],
            customer_id,
            data["customer_username"],
            data["policy_type"],
            data["coverage_amount"],
            data["premium"],
            data["start_date"],
            data["end_date"],
            data.get("status", "Active"),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        self.conn.commit()
        return self.cursor.lastrowid
    
    def get_all_policies(self) -> List[Dict]:
        """Get all policies"""
        self.cursor.execute('''
            SELECT * FROM policies ORDER BY created_at DESC
        ''')
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_policies_by_customer(self, username: str) -> List[Dict]:
        """Get policies for a specific customer"""
        self.cursor.execute('''
            SELECT * FROM policies WHERE customer_username = ? ORDER BY created_at DESC
        ''', (username,))
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_policy_by_id(self, policy_id: str) -> Optional[Dict]:
        """Get policy by policy_id"""
        self.cursor.execute("SELECT * FROM policies WHERE policy_id = ?", (policy_id,))
        result = self.cursor.fetchone()
        return dict(result) if result else None
    
    def update_policy(self, policy_id: str, updated_data: Dict) -> bool:
        """Update policy"""
        set_clause = []
        values = []
        for key, value in updated_data.items():
            set_clause.append(f"{key} = ?")
            values.append(value)
        
        values.append(policy_id)
        query = f"UPDATE policies SET {', '.join(set_clause)} WHERE policy_id = ?"
        
        self.cursor.execute(query, values)
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy"""
        self.cursor.execute("DELETE FROM policies WHERE policy_id = ?", (policy_id,))
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    # ============ CLAIM OPERATIONS ============
    def add_claim(self, data: Dict) -> int:
        """Add new claim"""
        customer_id = self._get_customer_id(data["customer_username"])
        if not customer_id:
            raise ValueError("Customer not found")
        
        if "claim_id" not in data:
            data["claim_id"] = str(uuid.uuid4())[:8]
        
        self.cursor.execute('''
            INSERT INTO claims (
                claim_id, customer_id, customer_username, policy_id, 
                claim_amount, reason, date_filed, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data["claim_id"],
            customer_id,
            data["customer_username"],
            data["policy_id"],
            data["claim_amount"],
            data.get("reason", ""),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            data.get("status", "Pending")
        ))
        self.conn.commit()
        return self.cursor.lastrowid
    
    def get_all_claims(self) -> List[Dict]:
        """Get all claims"""
        self.cursor.execute('''
            SELECT * FROM claims ORDER BY date_filed DESC
        ''')
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_claims_by_customer(self, username: str) -> List[Dict]:
        """Get claims for a specific customer"""
        self.cursor.execute('''
            SELECT * FROM claims WHERE customer_username = ? ORDER BY date_filed DESC
        ''', (username,))
        return [dict(row) for row in self.cursor.fetchall()]
    
    def update_claim_status(self, claim_id: str, status: str, admin_id: int = None, 
                           rejection_reason: str = None) -> bool:
        """Update claim status"""
        updates = {"status": status}
        if admin_id:
            updates["processed_by"] = admin_id
            updates["processed_date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if rejection_reason:
            updates["rejection_reason"] = rejection_reason
        
        set_clause = []
        values = []
        for key, value in updates.items():
            set_clause.append(f"{key} = ?")
            values.append(value)
        
        values.append(claim_id)
        query = f"UPDATE claims SET {', '.join(set_clause)} WHERE claim_id = ?"
        
        self.cursor.execute(query, values)
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    # ============ QUERY OPERATIONS ============
    def add_query(self, data: Dict) -> int:
        """Add new query"""
        customer_id = self._get_customer_id(data["customer_username"])
        if not customer_id:
            raise ValueError("Customer not found")
        
        if "query_id" not in data:
            data["query_id"] = str(uuid.uuid4())[:8]
        
        self.cursor.execute('''
            INSERT INTO queries (
                query_id, customer_id, customer_username, message, 
                date_submitted, status
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            data["query_id"],
            customer_id,
            data["customer_username"],
            data["message"],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            data.get("status", "Pending")
        ))
        self.conn.commit()
        return self.cursor.lastrowid
    
    def get_all_queries(self) -> List[Dict]:
        """Get all queries"""
        self.cursor.execute('''
            SELECT * FROM queries ORDER BY date_submitted DESC
        ''')
        return [dict(row) for row in self.cursor.fetchall()]
    
    def resolve_query(self, query_id: str, admin_id: int, admin_name: str, response: str = None) -> bool:
        """Resolve a query"""
        self.cursor.execute('''
            UPDATE queries SET 
                status = 'Resolved',
                resolved_by = ?,
                resolved_by_name = ?,
                resolved_date = ?,
                response = ?
            WHERE query_id = ?
        ''', (
            admin_id,
            admin_name,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            response,
            query_id
        ))
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    # ============ PAYMENT OPERATIONS ============
    def add_payment(self, data: Dict) -> int:
        """Add new payment"""
        customer_id = self._get_customer_id(data["customer_username"])
        if not customer_id:
            raise ValueError("Customer not found")
        
        if "payment_id" not in data:
            data["payment_id"] = str(uuid.uuid4())[:8]
        
        self.cursor.execute('''
            INSERT INTO payments (
                payment_id, customer_id, customer_username, policy_id,
                amount, payment_method, payment_date, status, transaction_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data["payment_id"],
            customer_id,
            data["customer_username"],
            data["policy_id"],
            data["amount"],
            data.get("payment_method", ""),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            data.get("status", "Completed"),
            data.get("transaction_id", str(uuid.uuid4())[:12])
        ))
        self.conn.commit()
        return self.cursor.lastrowid
    
    def get_all_payments(self) -> List[Dict]:
        """Get all payments"""
        self.cursor.execute('''
            SELECT * FROM payments ORDER BY payment_date DESC
        ''')
        return [dict(row) for row in self.cursor.fetchall()]
    
    def get_payments_by_customer(self, username: str) -> List[Dict]:
        """Get payments for a specific customer"""
        self.cursor.execute('''
            SELECT * FROM payments WHERE customer_username = ? ORDER BY payment_date DESC
        ''', (username,))
        return [dict(row) for row in self.cursor.fetchall()]
    
    # ============ AUDIT LOG ============
    def log_action(self, user: str, user_type: str, action: str, details: str = "", ip: str = None):
        """Log user action for audit"""
        self.cursor.execute('''
            INSERT INTO audit_log (timestamp, user, user_type, action, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            user,
            user_type,
            action,
            details,
            ip
        ))
        self.conn.commit()
    
    def get_audit_log(self, limit: int = 100) -> List[Dict]:
        """Get audit log entries"""
        self.cursor.execute('''
            SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        return [dict(row) for row in self.cursor.fetchall()]
    
    # ============ DASHBOARD STATISTICS ============
    def get_dashboard_stats(self) -> Dict:
        """Get dashboard statistics"""
        # Customer count
        self.cursor.execute("SELECT COUNT(*) FROM customers WHERE is_active = 1")
        total_customers = self.cursor.fetchone()[0]
        
        # Policy stats
        self.cursor.execute("SELECT COUNT(*) FROM policies")
        total_policies = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM policies WHERE status = 'Active'")
        active_policies = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT SUM(premium) FROM policies WHERE status = 'Active'")
        total_premium = self.cursor.fetchone()[0] or 0
        
        # Claim stats
        self.cursor.execute("SELECT COUNT(*) FROM claims")
        total_claims = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM claims WHERE status = 'Pending'")
        pending_claims = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT SUM(claim_amount) FROM claims WHERE status = 'Approved'")
        approved_claims_amount = self.cursor.fetchone()[0] or 0
        
        # Payment stats
        self.cursor.execute("SELECT SUM(amount) FROM payments WHERE status = 'Completed'")
        total_payments = self.cursor.fetchone()[0] or 0
        
        # Query stats
        self.cursor.execute("SELECT COUNT(*) FROM queries")
        total_queries = self.cursor.fetchone()[0]
        
        self.cursor.execute("SELECT COUNT(*) FROM queries WHERE status = 'Pending'")
        pending_queries = self.cursor.fetchone()[0]
        
        return {
            "total_customers": total_customers,
            "total_policies": total_policies,
            "active_policies": active_policies,
            "total_premium": total_premium,
            "total_claims": total_claims,
            "pending_claims": pending_claims,
            "approved_claims_amount": approved_claims_amount,
            "total_payments": total_payments,
            "total_queries": total_queries,
            "pending_queries": pending_queries
        }
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

# ============================================
# MODEL CLASSES
# ============================================
class InsurancePolicy:
    def __init__(self, policy_id=None, customer_username=None, policy_type=None, 
                 coverage_amount=0, premium=0, start_date=None, end_date=None):
        self.policy_id = policy_id or str(uuid.uuid4())[:8]
        self.customer_username = customer_username
        self.policy_type = policy_type
        self.coverage_amount = coverage_amount
        self.premium = premium
        self.start_date = start_date or datetime.now().strftime("%Y-%m-%d")
        self.end_date = end_date
        self.status = "Active"
    
    def to_dict(self):
        return {
            "policy_id": self.policy_id,
            "customer_username": self.customer_username,
            "policy_type": self.policy_type,
            "coverage_amount": self.coverage_amount,
            "premium": self.premium,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "status": self.status
        }

class Claim:
    def __init__(self, claim_id=None, customer_username=None, policy_id=None,
                 claim_amount=0, reason=""):
        self.claim_id = claim_id or str(uuid.uuid4())[:8]
        self.customer_username = customer_username
        self.policy_id = policy_id
        self.claim_amount = claim_amount
        self.reason = reason
        self.date_filed = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status = "Pending"
    
    def to_dict(self):
        return {
            "claim_id": self.claim_id,
            "customer_username": self.customer_username,
            "policy_id": self.policy_id,
            "claim_amount": self.claim_amount,
            "reason": self.reason,
            "date_filed": self.date_filed,
            "status": self.status
        }

class Query:
    def __init__(self, query_id=None, customer_username=None, message=""):
        self.query_id = query_id or str(uuid.uuid4())[:8]
        self.customer_username = customer_username
        self.message = message
        self.date_submitted = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status = "Pending"
    
    def to_dict(self):
        return {
            "query_id": self.query_id,
            "customer_username": self.customer_username,
            "message": self.message,
            "date_submitted": self.date_submitted,
            "status": self.status
        }

class Payment:
    def __init__(self, payment_id=None, customer_username=None, policy_id=None,
                 amount=0, payment_method=""):
        self.payment_id = payment_id or str(uuid.uuid4())[:8]
        self.customer_username = customer_username
        self.policy_id = policy_id
        self.amount = amount
        self.payment_method = payment_method
        self.payment_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.status = "Completed"
        self.transaction_id = str(uuid.uuid4())[:12]
    
    def to_dict(self):
        return {
            "payment_id": self.payment_id,
            "customer_username": self.customer_username,
            "policy_id": self.policy_id,
            "amount": self.amount,
            "payment_method": self.payment_method,
            "payment_date": self.payment_date,
            "status": self.status,
            "transaction_id": self.transaction_id
        }

# ============================================
# ADMIN PANEL CLASS
# ============================================
class AdminPanel:
    def __init__(self, db):
        self.db = db
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def admin_menu(self, admin):
        while True:
            self.clear_screen()
            print("\n" + "="*50)
            print(f" ==== ADMIN PANEL ====")
            print(f" Welcome {admin['name']} (ID: {admin['id']})")
            print("="*50)
            print("1. Add Policy")
            print("2. View Policies")
            print("3. Update Policy")
            print("4. Delete Policy")
            print("5. View Customers")
            print("6. View Claims")
            print("7. Process Claim")
            print("8. View Payments")
            print("9. Dashboard Statistics")
            print("10. Additional Features")
            print("11. View Audit Log")
            print("12. Logout")
            print("="*50)
            
            choice = input("Enter your choice (1-12): ")
            
            if choice == '1':
                self.add_policy(admin)
            elif choice == '2':
                self.view_policies()
            elif choice == '3':
                self.update_policy()
            elif choice == '4':
                self.delete_policy()
            elif choice == '5':
                self.view_customers()
            elif choice == '6':
                self.view_claims()
            elif choice == '7':
                self.process_claim(admin)
            elif choice == '8':
                self.view_payments()
            elif choice == '9':
                self.dashboard_statistics()
            elif choice == '10':
                self.additional_features(admin)
            elif choice == '11':
                self.view_audit_log()
            elif choice == '12':
                break
            else:
                print("Invalid choice!")
                input("\nPress Enter to continue...")
    
    def add_policy(self, admin):
        self.clear_screen()
        print("\n ==== ADD NEW POLICY ====")
        print("-"*40)
        
        customers = self.db.get_all_customers()
        if not customers:
            print("No customers available!")
            return
        
        print("\nAvailable Customers:")
        for i, c in enumerate(customers, 1):
            print(f"{i}. {c['username']} - {c.get('name', 'N/A')}")
        
        try:
            cust_choice = int(input("\nSelect customer number: ")) - 1
            customer_username = customers[cust_choice]['username']
        except (ValueError, IndexError):
            print("Invalid customer selection!")
            return
        
        print("\nPolicy Types Available:")
        print("1. Life Insurance")
        print("2. Health Insurance")
        print("3. Auto Insurance")
        print("4. Home Insurance")
        print("5. Travel Insurance")
        
        policy_types = {1: "Life", 2: "Health", 3: "Auto", 4: "Home", 5: "Travel"}
        
        try:
            type_choice = int(input("Select policy type (1-5): "))
            if type_choice not in policy_types:
                print("Invalid policy type!")
                return
            policy_type = policy_types[type_choice]
        except ValueError:
            print("Invalid input!")
            return
        
        try:
            coverage_amount = float(input("Coverage Amount: $"))
            premium = float(input("Premium Amount: $"))
            start_date = input("Start Date (YYYY-MM-DD): ")
            end_date = input("End Date (YYYY-MM-DD): ")
            
            policy = InsurancePolicy(
                customer_username=customer_username,
                policy_type=policy_type,
                coverage_amount=coverage_amount,
                premium=premium,
                start_date=start_date,
                end_date=end_date
            )
            
            self.db.add_policy(policy.to_dict())
            
            # Log the action
            self.db.log_action(
                admin['username'],
                'admin',
                'Add Policy',
                f"Created policy {policy.policy_id} for {customer_username}"
            )
            
            print(f"\n✓ Policy created successfully!")
            print(f"  Policy ID: {policy.policy_id}")
            print(f"  Customer: {customer_username}")
            print(f"  Type: {policy_type}")
            print(f"  Coverage: ${coverage_amount:,.2f}")
            print(f"  Premium: ${premium:,.2f}")
            
        except ValueError as e:
            print(f"Error: {e}")
    
    def view_policies(self):
        self.clear_screen()
        print("\n ==== VIEW ALL POLICIES ====")
        print("-"*100)
        
        policies = self.db.get_all_policies()
        if not policies:
            print("No policies found!")
            return
        
        print(f"{'Policy ID':<12} {'Customer':<15} {'Type':<12} {'Coverage':<15} {'Premium':<12} {'Start Date':<12} {'End Date':<12} {'Status':<10}")
        print("-"*100)
        
        for p in policies:
            print(f"{p['policy_id']:<12} {p['customer_username']:<15} {p['policy_type']:<12} "
                  f"${p['coverage_amount']:<14,.2f} ${p['premium']:<11,.2f} "
                  f"{p.get('start_date', 'N/A'):<12} {p.get('end_date', 'N/A'):<12} {p.get('status', 'Active'):<10}")
        
        total_premium = sum(p.get('premium', 0) for p in policies)
        active = len([p for p in policies if p.get('status') == 'Active'])
        print("\n" + "-"*100)
        print(f"Total Policies: {len(policies)} | Active: {active} | Total Premium: ${total_premium:,.2f}")
    
    def update_policy(self):
        self.clear_screen()
        print("\n ==== UPDATE POLICY ====")
        print("-"*40)
        
        policies = self.db.get_all_policies()
        if not policies:
            print("No policies available to update!")
            return
        
        print("\nAvailable Policies:")
        for i, p in enumerate(policies, 1):
            print(f"{i}. {p['policy_id']} - {p['customer_username']} - {p['policy_type']} (${p['premium']})")
        
        try:
            choice = int(input("\nSelect policy number (0 to cancel): "))
            if choice == 0:
                return
            policy = policies[choice-1]
            
            print(f"\nUpdating Policy: {policy['policy_id']}")
            print("\nLeave blank to keep current values")
            
            policy_type = input(f"Policy Type [{policy['policy_type']}]: ")
            coverage = input(f"Coverage Amount [{policy['coverage_amount']}]: ")
            premium = input(f"Premium [{policy['premium']}]: ")
            start_date = input(f"Start Date [{policy.get('start_date', '')}]: ")
            end_date = input(f"End Date [{policy.get('end_date', '')}]: ")
            status = input(f"Status [Active/Expired/Cancelled] [{policy.get('status', 'Active')}]: ")
            
            updated_data = {}
            if policy_type: updated_data['policy_type'] = policy_type
            if coverage: updated_data['coverage_amount'] = float(coverage)
            if premium: updated_data['premium'] = float(premium)
            if start_date: updated_data['start_date'] = start_date
            if end_date: updated_data['end_date'] = end_date
            if status: updated_data['status'] = status
            
            if self.db.update_policy(policy['policy_id'], updated_data):
                print("\n✓ Policy updated successfully!")
            else:
                print("\n✗ Failed to update policy!")
                
        except (ValueError, IndexError) as e:
            print(f"Error: {e}")
    
    def delete_policy(self):
        self.clear_screen()
        print("\n ==== DELETE POLICY ====")
        print("-"*40)
        
        policies = self.db.get_all_policies()
        if not policies:
            print("No policies available to delete!")
            return
        
        print("\nAvailable Policies:")
        for i, p in enumerate(policies, 1):
            print(f"{i}. {p['policy_id']} - {p['customer_username']} - {p['policy_type']} (${p['premium']})")
        
        try:
            choice = int(input("\nSelect policy number to delete (0 to cancel): "))
            if choice == 0:
                return
            
            policy = policies[choice-1]
            confirm = input(f"\nAre you sure you want to delete policy {policy['policy_id']}? (yes/no): ")
            
            if confirm.lower() == 'yes':
                if self.db.delete_policy(policy['policy_id']):
                    print("\n✓ Policy deleted successfully!")
                else:
                    print("\n✗ Failed to delete policy!")
            else:
                print("\nDeletion cancelled.")
                
        except (ValueError, IndexError):
            print("Invalid selection!")
    
    def view_customers(self):
        self.clear_screen()
        print("\n ==== VIEW ALL CUSTOMERS ====")
        print("-"*90)
        
        customers = self.db.get_all_customers()
        if not customers:
            print("No customers found!")
            return
        
        print(f"{'ID':<5} {'Username':<15} {'Name':<20} {'Email':<25} {'Phone':<15} {'Status':<10}")
        print("-"*90)
        
        for c in customers:
            status = "Active" if c.get('is_active', 1) else "Inactive"
            print(f"{c['id']:<5} {c['username']:<15} {c.get('name','N/A'):<20} {c.get('email','N/A'):<25} "
                  f"{c.get('phone','N/A'):<15} {status:<10}")
        
        print(f"\nTotal Customers: {len(customers)}")
    
    def view_claims(self):
        self.clear_screen()
        print("\n ==== VIEW ALL CLAIMS ====")
        print("-"*100)
        
        claims = self.db.get_all_claims()
        if not claims:
            print("No claims found!")
            return
        
        print(f"{'Claim ID':<12} {'Customer':<15} {'Policy ID':<12} {'Amount':<12} {'Status':<12} {'Date':<20} {'Reason':<20}")
        print("-"*100)
        
        for c in claims:
            print(f"{c['claim_id']:<12} {c['customer_username']:<15} {c['policy_id']:<12} "
                  f"${c['claim_amount']:<11,.2f} {c['status']:<12} {c['date_filed']:<20} {c.get('reason', 'N/A')[:20]:<20}")
        
        pending = len([c for c in claims if c['status'] == 'Pending'])
        approved = len([c for c in claims if c['status'] == 'Approved'])
        rejected = len([c for c in claims if c['status'] == 'Rejected'])
        total_amount = sum(c['claim_amount'] for c in claims if c['status'] == 'Approved')
        
        print("\n" + "-"*100)
        print(f"Summary: Pending: {pending} | Approved: {approved} | Rejected: {rejected} | Total Approved: ${total_amount:,.2f}")
    
    def process_claim(self, admin):
        self.clear_screen()
        print("\n ==== PROCESS CLAIMS ====")
        print("-"*40)
        
        claims = self.db.get_all_claims()
        pending_claims = [c for c in claims if c['status'] == 'Pending']
        
        if not pending_claims:
            print("No pending claims to process!")
            return
        
        print("\nPending Claims:")
        for i, c in enumerate(pending_claims, 1):
            print(f"\n{i}. Claim ID: {c['claim_id']}")
            print(f"   Customer: {c['customer_username']}")
            print(f"   Policy ID: {c['policy_id']}")
            print(f"   Amount: ${c['claim_amount']:,.2f}")
            print(f"   Reason: {c.get('reason', 'N/A')}")
            print(f"   Date Filed: {c['date_filed']}")
        
        try:
            choice = int(input("\nSelect claim to process (0 to cancel): "))
            if choice == 0:
                return
            
            claim = pending_claims[choice-1]
            
            print(f"\nProcessing Claim: {claim['claim_id']}")
            print(f"Amount: ${claim['claim_amount']:,.2f}")
            print("\nOptions:")
            print("1. Approve Claim")
            print("2. Reject Claim")
            print("3. Request More Information")
            
            action = input("Select action (1-3): ")
            
            if action == '1':
                self.db.update_claim_status(claim['claim_id'], 'Approved', admin['id'])
                self.db.log_action(
                    admin['username'],
                    'admin',
                    'Approve Claim',
                    f"Approved claim {claim['claim_id']} for ${claim['claim_amount']:,.2f}"
                )
                print("\n✓ Claim Approved!")
                
                add_payment = input("Add payment record? (yes/no): ")
                if add_payment.lower() == 'yes':
                    payment = Payment(
                        customer_username=claim['customer_username'],
                        policy_id=claim['policy_id'],
                        amount=claim['claim_amount'],
                        payment_method="Claim Settlement"
                    )
                    self.db.add_payment(payment.to_dict())
                    print("✓ Payment record created!")
                    
            elif action == '2':
                rejection_reason = input("Enter rejection reason: ")
                self.db.update_claim_status(claim['claim_id'], 'Rejected', admin['id'], rejection_reason)
                self.db.log_action(
                    admin['username'],
                    'admin',
                    'Reject Claim',
                    f"Rejected claim {claim['claim_id']} - Reason: {rejection_reason}"
                )
                print("\n✓ Claim Rejected!")
                
            elif action == '3':
                self.db.update_claim_status(claim['claim_id'], 'Info Requested', admin['id'])
                print("\n✓ Status updated to 'Info Requested'")
                
            else:
                print("Invalid action!")
                
        except (ValueError, IndexError) as e:
            print(f"Error: {e}")
    
    def view_payments(self):
        self.clear_screen()
        print("\n ==== VIEW PAYMENTS ====")
        print("-"*100)
        
        payments = self.db.get_all_payments()
        if not payments:
            print("No payments recorded yet!")
            return
        
        print(f"{'Payment ID':<12} {'Customer':<15} {'Policy ID':<12} {'Amount':<12} {'Method':<15} {'Date':<20} {'Status':<10}")
        print("-"*100)
        
        for p in payments:
            print(f"{p['payment_id']:<12} {p['customer_username']:<15} {p['policy_id']:<12} "
                  f"${p['amount']:<11,.2f} {p.get('payment_method', 'N/A'):<15} "
                  f"{p['payment_date']:<20} {p.get('status', 'Completed'):<10}")
        
        total_payments = sum(p['amount'] for p in payments)
        print("\n" + "-"*100)
        print(f"Total Payments: {len(payments)} | Total Amount: ${total_payments:,.2f}")
    
    def dashboard_statistics(self):
        self.clear_screen()
        print("\n" + "="*50)
        print(" ==== DASHBOARD STATISTICS ====")
        print("="*50)
        
        stats = self.db.get_dashboard_stats()
        
        print("\n📊 OVERVIEW")
        print("-"*50)
        print(f"Total Customers:        {stats['total_customers']}")
        print(f"Total Policies:         {stats['total_policies']}")
        print(f"Active Policies:        {stats['active_policies']}")
        print(f"Total Premium:          ${stats['total_premium']:,.2f}")
        
        print("\n📋 CLAIMS")
        print("-"*50)
        print(f"Total Claims:           {stats['total_claims']}")
        print(f"Pending Claims:         {stats['pending_claims']}")
        print(f"Approved Claims Amount: ${stats['approved_claims_amount']:,.2f}")
        
        print("\n💰 FINANCIAL")
        print("-"*50)
        print(f"Total Premium Collected: ${stats['total_premium']:,.2f}")
        print(f"Total Payments Made:     ${stats['total_payments']:,.2f}")
        print(f"Net Balance:             ${stats['total_premium'] - stats['total_payments']:,.2f}")
        
        print("\n🎫 SUPPORT")
        print("-"*50)
        print(f"Total Queries:          {stats['total_queries']}")
        print(f"Pending Queries:        {stats['pending_queries']}")
        
        if stats['total_policies'] > 0:
            active_rate = (stats['active_policies'] / stats['total_policies']) * 100
            print(f"\n📈 Policy Active Rate:     {active_rate:.1f}%")
    
    def additional_features(self, admin):
        while True:
            self.clear_screen()
            print("\n" + "="*50)
            print(" ==== ADDITIONAL FEATURES ====")
            print("="*50)
            print("1. View Queries")
            print("2. Resolve Queries")
            print("3. Add New Customer")
            print("4. Deactivate Customer")
            print("5. Generate Reports")
            print("6. Back to Main Menu")
            print("="*50)
            
            choice = input("Enter your choice (1-6): ")
            
            if choice == '1':
                self.view_queries()
            elif choice == '2':
                self.resolve_queries(admin)
            elif choice == '3':
                self.add_new_customer(admin)
            elif choice == '4':
                self.deactivate_customer(admin)
            elif choice == '5':
                self.generate_reports()
            elif choice == '6':
                break
            else:
                print("Invalid choice!")
            input("\nPress Enter to continue...")
    
    def view_queries(self):
        self.clear_screen()
        print("\n ==== CUSTOMER QUERIES ====")
        print("-"*120)
        print(f"{'Query ID':<12} {'Customer':<15} {'Message':<50} {'Status':<12} {'Submitted':<20} {'Resolved By':<15}")
        print("-"*120)
        
        queries = self.db.get_all_queries()
        if not queries:
            print("No queries found!")
            return
        
        for q in queries:
            resolved = q.get('resolved_by_name', 'N/A')
            # Truncate message to fit in the display
            message = q['message'][:47] + "..." if len(q['message']) > 50 else q['message']
            print(f"{q['query_id']:<12} {q['customer_username']:<15} {message:<50} "
                  f"{q['status']:<12} {q['date_submitted'][:19]:<20} {resolved:<15}")
        
        print("\n" + "-"*120)
        pending = len([q for q in queries if q['status'] == 'Pending'])
        resolved = len([q for q in queries if q['status'] == 'Resolved'])
        print(f"Total Queries: {len(queries)} | Pending: {pending} | Resolved: {resolved}")
    
    def resolve_queries(self, admin):
        self.clear_screen()
        print("\n ==== RESOLVE QUERIES ====")
        print("-"*40)
        
        queries = self.db.get_all_queries()
        pending = [q for q in queries if q['status'] == 'Pending']
        
        if not pending:
            print("No pending queries!")
            return
        
        print("\nPending Queries:")
        for i, q in enumerate(pending, 1):
            print(f"\n{i}. Query ID: {q['query_id']}")
            print(f"   Customer: {q['customer_username']}")
            print(f"   Message: {q['message']}")
            print(f"   Date: {q['date_submitted']}")
        
        try:
            choice = int(input("\nSelect query to resolve (0 to cancel): "))
            if choice == 0:
                return
            query = pending[choice-1]
            
            response = input("Enter response message: ")
            
            self.db.resolve_query(query['query_id'], admin['id'], admin['name'], response)
            self.db.log_action(
                admin['username'],
                'admin',
                'Resolve Query',
                f"Resolved query {query['query_id']}"
            )
            print(f"\n✓ Query resolved successfully by {admin['name']}!")
        except (ValueError, IndexError):
            print("Invalid selection!")
    
    def add_new_customer(self, admin):
        self.clear_screen()
        print("\n ==== ADD NEW CUSTOMER ====")
        print("-"*40)
        
        try:
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            confirm_password = getpass.getpass("Confirm Password: ")
            
            if password != confirm_password:
                print("\n✗ Passwords do not match!")
                return
            
            name = input("Full Name: ")
            email = input("Email: ")
            phone = input("Phone: ")
            address = input("Address: ")
            
            customer = {
                "username": username,
                "password": password,
                "name": name,
                "email": email,
                "phone": phone,
                "address": address
            }
            
            customer_id = self.db.add_customer(customer)
            self.db.log_action(
                admin['username'],
                'admin',
                'Add Customer',
                f"Added customer {username} (ID: {customer_id})"
            )
            print(f"\n✓ Customer {name} added successfully!")
            
        except ValueError as e:
            print(f"\n✗ Error: {e}")
    
    def deactivate_customer(self, admin):
        self.clear_screen()
        print("\n ==== DEACTIVATE CUSTOMER ====")
        print("-"*40)
        
        customers = self.db.get_all_customers()
        active_customers = [c for c in customers if c.get('is_active', 1)]
        
        if not active_customers:
            print("No active customers found!")
            return
        
        print("\nActive Customers:")
        for i, c in enumerate(active_customers, 1):
            print(f"{i}. {c['username']} - {c['name']} ({c['email']})")
        
        try:
            choice = int(input("\nSelect customer to deactivate (0 to cancel): "))
            if choice == 0:
                return
            
            customer = active_customers[choice-1]
            confirm = input(f"\nAre you sure you want to deactivate {customer['username']}? (yes/no): ")
            
            if confirm.lower() == 'yes':
                if self.db.deactivate_customer(customer['username']):
                    self.db.log_action(
                        admin['username'],
                        'admin',
                        'Deactivate Customer',
                        f"Deactivated customer {customer['username']}"
                    )
                    print("\n✓ Customer deactivated successfully!")
                else:
                    print("\n✗ Failed to deactivate customer!")
            else:
                print("\nOperation cancelled.")
                
        except (ValueError, IndexError):
            print("Invalid selection!")
    
    def generate_reports(self):
        self.clear_screen()
        print("\n ==== SYSTEM REPORTS ====")
        print("="*50)
        
        customers = self.db.get_all_customers()
        policies = self.db.get_all_policies()
        claims = self.db.get_all_claims()
        queries = self.db.get_all_queries()
        payments = self.db.get_all_payments()
        
        total_premium = sum(p.get('premium', 0) for p in policies)
        approved_claims = sum(c.get('claim_amount', 0) for c in claims if c.get('status') == 'Approved')
        resolved_queries = len([q for q in queries if q.get('status') == 'Resolved'])
        total_payments = sum(p.get('amount', 0) for p in payments)
        
        print(f"\n📊 SYSTEM OVERVIEW")
        print(f"   Total Customers: {len(customers)}")
        print(f"   Total Policies: {len(policies)}")
        print(f"   Total Premium Collected: ${total_premium:,.2f}")
        print(f"   Total Claims Filed: {len(claims)}")
        print(f"   Approved Claims Amount: ${approved_claims:,.2f}")
        print(f"   Total Payments Made: ${total_payments:,.2f}")
        print(f"   Total Queries: {len(queries)}")
        print(f"   Resolved Queries: {resolved_queries}")
        print(f"   Pending Queries: {len(queries) - resolved_queries}")
    
    def view_audit_log(self):
        self.clear_screen()
        print("\n ==== AUDIT LOG ====")
        print("-"*120)
        
        logs = self.db.get_audit_log(50)
        if not logs:
            print("No audit records found!")
            return
        
        print(f"{'Timestamp':<20} {'User':<15} {'Type':<10} {'Action':<25} {'Details':<45}")
        print("-"*120)
        
        for log in logs:
            details = log.get('details', '')[:42] + "..." if len(log.get('details', '')) > 45 else log.get('details', '')
            print(f"{log['timestamp']:<20} {log['user']:<15} {log['user_type']:<10} "
                  f"{log['action']:<25} {details:<45}")

# ============================================
# CUSTOMER PANEL CLASS
# ============================================
class CustomerPanel:
    def __init__(self, db):
        self.db = db
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def customer_menu(self, customer):
        while True:
            self.clear_screen()
            print("\n" + "="*50)
            print(f" ==== CUSTOMER PANEL ====")
            print(f" Welcome {customer['name']}")
            print("="*50)
            print("1. View Available Policies")
            print("2. My Purchased Policies")
            print("3. Buy Policy")
            print("4. Make Payment")
            print("5. Submit Claim")
            print("6. My Claim History")
            print("7. My Payment History")
            print("8. Update Profile")
            print("9. Submit Query")
            print("10. View Query Status")
            print("11. Logout")
            print("="*50)
            
            choice = input("Enter your choice (1-11): ")
            
            if choice == '1':
                self.view_available_policies()
            elif choice == '2':
                self.my_purchased_policies(customer['username'])
            elif choice == '3':
                self.buy_policy(customer['username'])
            elif choice == '4':
                self.make_payment(customer['username'])
            elif choice == '5':
                self.submit_claim(customer['username'])
            elif choice == '6':
                self.my_claim_history(customer['username'])
            elif choice == '7':
                self.my_payment_history(customer['username'])
            elif choice == '8':
                self.update_profile(customer)
            elif choice == '9':
                self.submit_query(customer['username'])
            elif choice == '10':
                self.view_query_status(customer['username'])
            elif choice == '11':
                break
            else:
                print(" Invalid choice!")
            input("\nPress Enter to continue...")
    
    def view_available_policies(self):
        self.clear_screen()
        print("\n ==== AVAILABLE INSURANCE POLICIES ====")
        print("-"*80)
        
        print("\n📋 LIFE INSURANCE")
        print("-"*40)
        print(f"{'Plan':<20} {'Coverage':<15} {'Annual Premium':<20} {'Monthly':<15} {'Duration':<15}")
        print("-"*40)
        print(f"{'Basic Life':<20} {'$100,000':<15} {'$600':<20} {'$500':<15} {'10-30 years':<15}")
        print(f"{'Premium Life':<20} {'$250,000':<15} {'$1,200':<20} {'$100':<15} {'15-35 years':<15}")
        print(f"{'Gold Life':<20} {'$500,000':<15} {'$2,100':<20} {'$175':<15} {'20-40 years':<15}")
        print(f"{'Platinum Life':<20} {'$1,000,000':<15} {'$3,600':<20} {'$300':<15} {'25-50 years':<15}")
        
        print("\n📋 HEALTH INSURANCE")
        print("-"*40)
        print(f"{'Plan':<20} {'Coverage':<15} {'Annual Premium':<20} {'Monthly':<15} {'Duration':<15}")
        print("-"*40)
        print(f"{'Basic Health':<20} {'$50,000':<15} {'$1,200':<20} {'$100':<15} {'Annual':<15}")
        print(f"{'Family Health':<20} {'$150,000':<15} {'$2,400':<20} {'$200':<15} {'Annual':<15}")
        print(f"{'Premium Health':<20} {'$300,000':<15} {'$4,200':<20} {'$350':<15} {'Annual':<15}")
        print(f"{'Global Health':<20} {'$500,000':<15} {'$6,600':<20} {'$550':<15} {'Annual':<15}")
        
        print("\n📋 AUTO INSURANCE")
        print("-"*40)
        print(f"{'Plan':<20} {'Coverage':<15} {'Annual Premium':<20} {'Monthly':<15} {'Duration':<15}")
        print("-"*40)
        print(f"{'Third Party':<20} {'$30,000':<15} {'$600':<20} {'$100':<15} {'Annual':<15}")
        print(f"{'Comprehensive':<20} {'$75,000':<15} {'$970':<20} {'$100':<15} {'Annual':<15}")
        print(f"{'Premium Auto':<20} {'$150,000':<15} {'$1,800':<20} {'$150':<15} {'Annual':<15}")
        print(f"{'Luxury Auto':<20} {'$300,000':<15} {'$2,400':<20} {'$200':<15} {'Annual':<15}")
        
        print("\n📋 HOME INSURANCE")
        print("-"*40)
        print(f"{'Plan':<20} {'Coverage':<15} {'Annual Premium':<20} {'Monthly':<15} {'Duration':<15}")
        print("-"*40)
        print(f"{'Basic Home':<20} {'$150,000':<15} {'$7000':<20} {'$600':<15} {'Annual':<15}")
        print(f"{'Standard Home':<20} {'$300,000':<15} {'$20,000':<20} {'$1660':<15} {'Annual':<15}")
        print(f"{'Premium Home':<20} {'$500,000':<15} {'$50,000':<20} {'$4,175':<15} {'Annual':<15}")
        print(f"{'Luxury Home':<20} {'$1,000,000':<15} {'$10,000':<20} {'$830':<15} {'Annual':<15}")
        
        print("\n📋 TRAVEL INSURANCE")
        print("-"*40)
        print(f"{'Plan':<20} {'Coverage':<15} {'Premium/Trip':<20} {'Annual':<15} {'Duration':<15}")
        print("-"*40)
        print(f"{'Basic Travel':<20} {'$25,000':<15} {'$500':<20} {'$2000':<15} {'Per Trip':<15}")
        print(f"{'Standard Travel':<20} {'$75,000':<15} {'$130':<20} {'$1,500':<15} {'Per Trip':<15}")
        print(f"{'Premium Travel':<20} {'$150,000':<15} {'$300':<20} {'$3,000':<15} {'Per Trip':<15}")
        print(f"{'Global Travel':<20} {'$300,000':<15} {'$3500':<20} {'$21,000':<15} {'Per Trip':<15}")
        
        print("\n" + "="*80)
        print("📝 Note: Premiums are calculated based on coverage amount and risk factors.")
        print("To purchase a policy, select option 3: 'Buy Policy' from the main menu.")
    
    def my_purchased_policies(self, username):
        self.clear_screen()
        print("\n ==== MY PURCHASED POLICIES ====")
        print("-"*120)
        
        policies = self.db.get_policies_by_customer(username)
        
        if not policies:
            print("You haven't purchased any policies yet!")
            return
        
        print(f"{'Policy ID':<12} {'Type':<12} {'Coverage':<15} {'Monthly Premium':<15} {'Annual Premium':<15} {'Status':<10} {'Start Date':<12} {'End Date':<12}")
        print("-"*120)
        
        for p in policies:
            annual = p['premium'] * 12
            print(f"{p['policy_id']:<12} {p['policy_type']:<12} "
                  f"${p['coverage_amount']:<14,.2f} ${p['premium']:<14,.2f} ${annual:<14,.2f} "
                  f"{p.get('status', 'Active'):<10} {p.get('start_date', 'N/A'):<12} {p.get('end_date', 'N/A'):<12}")
        
        total_premium = sum(p['premium'] for p in policies)
        active_policies = len([p for p in policies if p.get('status') == 'Active'])
        total_annual = total_premium * 12
        
        print("\n" + "-"*120)
        print(f"Total Policies: {len(policies)} | Active: {active_policies} | Total Monthly Premium: ${total_premium:,.2f} | Total Annual Premium: ${total_annual:,.2f}")
    
    def buy_policy(self, username):
        self.clear_screen()
        print("\n ==== BUY INSURANCE POLICY ====")
        print("-"*40)
        
        print("\nSelect Insurance Type:")
        print("1. Life Insurance")
        print("2. Health Insurance")
        print("3. Auto Insurance")
        print("4. Home Insurance")
        print("5. Travel Insurance")
        
        try:
            type_choice = int(input("\nSelect type (1-5): "))
            
            policy_details = {
                1: {
                    "name": "Life Insurance",
                    "plans": {
                        1: {"name": "Basic Life", "coverage": 100000, "premium": 500},
                        2: {"name": "Premium Life", "coverage": 250000, "premium": 100},
                        3: {"name": "Gold Life", "coverage": 500000, "premium": 175},
                        4: {"name": "Platinum Life", "coverage": 1000000, "premium": 300}
                    },
                    "duration": "10-50 years"
                },
                2: {
                    "name": "Health Insurance",
                    "plans": {
                        1: {"name": "Basic Health", "coverage": 50000, "premium": 100},
                        2: {"name": "Family Health", "coverage": 150000, "premium": 200},
                        3: {"name": "Premium Health", "coverage": 300000, "premium": 350},
                        4: {"name": "Global Health", "coverage": 500000, "premium": 550}
                    },
                    "duration": "Annual"
                },
                3: {
                    "name": "Auto Insurance",
                    "plans": {
                        1: {"name": "Third Party", "coverage": 30000, "premium": 100},
                        2: {"name": "Comprehensive", "coverage": 75000, "premium": 100},
                        3: {"name": "Premium Auto", "coverage": 150000, "premium": 150},
                        4: {"name": "Luxury Auto", "coverage": 300000, "premium": 200}
                    },
                    "duration": "Annual"
                },
                4: {
                    "name": "Home Insurance",
                    "plans": {
                        1: {"name": "Basic Home", "coverage": 150000, "premium": 600},
                        2: {"name": "Standard Home", "coverage": 300000, "premium": 1660},
                        3: {"name": "Premium Home", "coverage": 500000, "premium": 4175},
                        4: {"name": "Luxury Home", "coverage": 1000000, "premium": 830}
                    },
                    "duration": "Annual"
                },
                5: {
                    "name": "Travel Insurance",
                    "plans": {
                        1: {"name": "Basic Travel", "coverage": 25000, "premium": 500},
                        2: {"name": "Standard Travel", "coverage": 75000, "premium": 130},
                        3: {"name": "Premium Travel", "coverage": 150000, "premium": 300},
                        4: {"name": "Global Travel", "coverage": 300000, "premium": 3500}
                    },
                    "duration": "Per Trip"
                }
            }
            
            if type_choice not in policy_details:
                print("Invalid insurance type!")
                return
            
            selected_type = policy_details[type_choice]
            
            print(f"\n📋 {selected_type['name']} Plans:")
            print("-"*70)
            print(f"{'#':<5} {'Plan':<20} {'Coverage':<15} {'Monthly Premium':<20} {'Duration':<15}")
            print("-"*70)
            
            for key, plan in selected_type['plans'].items():
                print(f"{key:<5} {plan['name']:<20} ${plan['coverage']:<14,} ${plan['premium']:<19,.2f} {selected_type['duration']:<15}")
            
            plan_choice = int(input("\nSelect plan (1-4): "))
            
            if plan_choice not in selected_type['plans']:
                print("Invalid plan selection!")
                return
            
            selected_plan = selected_type['plans'][plan_choice]
            
            print(f"\nSelected Plan: {selected_plan['name']}")
            print(f"Coverage: ${selected_plan['coverage']:,.2f}")
            print(f"Monthly Premium: ${selected_plan['premium']:,.2f}")
            print(f"Annual Premium: ${selected_plan['premium'] * 12:,.2f}")
            print(f"Duration: {selected_type['duration']}")
            
            confirm = input("\nConfirm purchase? (yes/no): ")
            
            if confirm.lower() == 'yes':
                start_date = datetime.now().strftime("%Y-%m-%d")
                
                if type_choice == 1:
                    end_date = f"{datetime.now().year + 20}-{datetime.now().strftime('%m-%d')}"
                else:
                    end_date = f"{datetime.now().year + 1}-{datetime.now().strftime('%m-%d')}"
                
                policy = InsurancePolicy(
                    customer_username=username,
                    policy_type=selected_type['name'],
                    coverage_amount=selected_plan['coverage'],
                    premium=selected_plan['premium'],
                    start_date=start_date,
                    end_date=end_date
                )
                
                self.db.add_policy(policy.to_dict())
                
                payment = Payment(
                    customer_username=username,
                    policy_id=policy.policy_id,
                    amount=selected_plan['premium'],
                    payment_method="Policy Purchase"
                )
                self.db.add_payment(payment.to_dict())
                
                print("\n" + "="*50)
                print("✓ POLICY PURCHASED SUCCESSFULLY!")
                print("="*50)
                print(f"\nPolicy Details:")
                print(f"  Policy ID: {policy.policy_id}")
                print(f"  Type: {selected_type['name']}")
                print(f"  Plan: {selected_plan['name']}")
                print(f"  Coverage: ${selected_plan['coverage']:,.2f}")
                print(f"  Monthly Premium: ${selected_plan['premium']:,.2f}")
                print(f"  Annual Premium: ${selected_plan['premium'] * 12:,.2f}")
                print(f"  Start Date: {start_date}")
                print(f"  End Date: {end_date}")
                print(f"\nFirst payment of ${selected_plan['premium']:,.2f} has been processed.")
            else:
                print("\nPurchase cancelled.")
                
        except ValueError as e:
            print(f"Error: {e}")
    
    def make_payment(self, username):
        self.clear_screen()
        print("\n ==== MAKE PAYMENT ====")
        print("-"*40)
        
        policies = self.db.get_policies_by_customer(username)
        my_policies = [p for p in policies if p.get('status') == 'Active']
        
        if not my_policies:
            print("You don't have any active policies!")
            return
        
        print("\nYour Active Policies:")
        print("-"*70)
        for i, p in enumerate(my_policies, 1):
            annual_premium = p['premium'] * 12
            print(f"{i}. Policy ID: {p['policy_id']} - {p['policy_type']}")
            print(f"   Coverage: ${p['coverage_amount']:,.2f} | Monthly: ${p['premium']:,.2f} | Annual: ${annual_premium:,.2f}")
        
        try:
            choice = int(input("\nSelect policy to make payment (0 to cancel): "))
            if choice == 0:
                return
            
            selected_policy = my_policies[choice-1]
            
            print(f"\nSelected Policy: {selected_policy['policy_id']}")
            print(f"Monthly Premium Due: ${selected_policy['premium']:,.2f}")
            print(f"Annual Premium Due: ${selected_policy['premium'] * 12:,.2f}")
            
            print("\nPayment Options:")
            print("1. Pay Monthly Premium")
            print("2. Pay Annual Premium (Save 10%)")
            
            payment_option = int(input("Select payment option (1-2): "))
            
            if payment_option == 1:
                amount = selected_policy['premium']
                print(f"\nAmount: ${amount:,.2f}")
            elif payment_option == 2:
                amount = selected_policy['premium'] * 12 * 0.9  # 10% discount for annual payment
                print(f"\nAmount: ${amount:,.2f} (10% discount applied)")
            else:
                print("Invalid option!")
                return
            
            print("\nPayment Methods:")
            print("1. Credit/Debit Card")
            print("2. Bank Transfer")
            print("3. Mobile Payment")
            print("4. Cash")
            
            payment_methods = {
                1: "Credit/Debit Card",
                2: "Bank Transfer",
                3: "Mobile Payment",
                4: "Cash"
            }
            
            method_choice = int(input("Select payment method (1-4): "))
            
            if method_choice not in payment_methods:
                print("Invalid payment method!")
                return
            
            payment_method = payment_methods[method_choice]
            
            confirm = input(f"\nConfirm payment of ${amount:,.2f} via {payment_method}? (yes/no): ")
            
            if confirm.lower() == 'yes':
                payment = Payment(
                    customer_username=username,
                    policy_id=selected_policy['policy_id'],
                    amount=amount,
                    payment_method=payment_method
                )
                
                self.db.add_payment(payment.to_dict())
                
                print("\n" + "="*50)
                print("✓ PAYMENT SUCCESSFUL!")
                print("="*50)
                print(f"\nPayment Details:")
                print(f"  Payment ID: {payment.payment_id}")
                print(f"  Transaction ID: {payment.transaction_id}")
                print(f"  Policy ID: {selected_policy['policy_id']}")
                print(f"  Amount: ${amount:,.2f}")
                print(f"  Method: {payment_method}")
                print(f"  Date: {payment.payment_date}")
                print(f"  Status: Completed")
            else:
                print("\nPayment cancelled.")
                
        except ValueError as e:
            print(f"Error: {e}")
    
    def submit_claim(self, username):
        self.clear_screen()
        print("\n ==== SUBMIT CLAIM ====")
        print("-"*40)
        
        policies = self.db.get_policies_by_customer(username)
        my_policies = [p for p in policies if p.get('status') == 'Active']
        
        if not my_policies:
            print("You don't have any active policies to claim against!")
            return
        
        print("\nYour Active Policies:")
        print("-"*60)
        for i, p in enumerate(my_policies, 1):
            print(f"{i}. {p['policy_id']} - {p['policy_type']} (Coverage: ${p['coverage_amount']:,.2f})")
        
        try:
            choice = int(input("\nSelect policy for claim (0 to cancel): "))
            if choice == 0:
                return
            
            selected_policy = my_policies[choice-1]
            
            print(f"\nSelected Policy: {selected_policy['policy_id']} - {selected_policy['policy_type']}")
            print(f"Maximum Coverage: ${selected_policy['coverage_amount']:,.2f}")
            
            claim_amount = float(input("\nClaim Amount: $"))
            
            if claim_amount <= 0:
                print("Invalid claim amount!")
                return
            
            if claim_amount > selected_policy['coverage_amount']:
                print(f"⚠️ Warning: Claim amount exceeds coverage of ${selected_policy['coverage_amount']:,.2f}")
                proceed = input("Do you still want to proceed? (yes/no): ")
                if proceed.lower() != 'yes':
                    print("Claim cancelled.")
                    return
            
            print("\nClaim Reasons:")
            print("1. Accident")
            print("2. Medical Emergency")
            print("3. Property Damage")
            print("4. Theft/Burglary")
            print("5. Natural Disaster")
            print("6. Other")
            
            reason_choice = int(input("Select reason (1-6): "))
            
            reasons = {
                1: "Accident",
                2: "Medical Emergency",
                3: "Property Damage",
                4: "Theft/Burglary",
                5: "Natural Disaster",
                6: "Other"
            }
            
            reason = reasons.get(reason_choice, "Other")
            
            if reason == "Other":
                reason = input("Please specify reason: ")
            
            print(f"\nClaim Summary:")
            print(f"  Policy: {selected_policy['policy_id']}")
            print(f"  Amount: ${claim_amount:,.2f}")
            print(f"  Reason: {reason}")
            print(f"  Coverage Available: ${selected_policy['coverage_amount']:,.2f}")
            if claim_amount <= selected_policy['coverage_amount']:
                print(f"  Status: ✅ Within coverage limit")
            else:
                print(f"  Status: ⚠️ Exceeds coverage limit")
            
            confirm = input("\nSubmit claim? (yes/no): ")
            
            if confirm.lower() == 'yes':
                claim = Claim(
                    customer_username=username,
                    policy_id=selected_policy['policy_id'],
                    claim_amount=claim_amount,
                    reason=reason
                )
                
                self.db.add_claim(claim.to_dict())
                
                print("\n" + "="*50)
                print("✓ CLAIM SUBMITTED SUCCESSFULLY!")
                print("="*50)
                print(f"\nClaim Details:")
                print(f"  Claim ID: {claim.claim_id}")
                print(f"  Policy ID: {claim.policy_id}")
                print(f"  Amount: ${claim_amount:,.2f}")
                print(f"  Reason: {reason}")
                print(f"  Status: Pending")
                print(f"  Date: {claim.date_filed}")
                print(f"\nYour claim will be reviewed by our team within 2-3 business days.")
            else:
                print("\nClaim submission cancelled.")
                
        except ValueError as e:
            print(f"Error: {e}")
    
    def my_claim_history(self, username):
        self.clear_screen()
        print("\n ==== MY CLAIM HISTORY ====")
        print("-"*100)
        
        claims = self.db.get_claims_by_customer(username)
        
        if not claims:
            print("No claims filed yet!")
            return
        
        print(f"{'Claim ID':<12} {'Policy ID':<12} {'Amount':<12} {'Reason':<20} {'Status':<12} {'Date':<20}")
        print("-"*100)
        
        for c in claims:
            status_symbol = "🟢" if c['status'] == 'Approved' else "🔴" if c['status'] == 'Rejected' else "🟡"
            print(f"{c['claim_id']:<12} {c['policy_id']:<12} ${c['claim_amount']:<11,.2f} "
                  f"{c.get('reason', 'N/A')[:20]:<20} {status_symbol} {c['status']:<10} {c['date_filed']:<20}")
        
        total_claims = len(claims)
        approved = len([c for c in claims if c['status'] == 'Approved'])
        rejected = len([c for c in claims if c['status'] == 'Rejected'])
        pending = len([c for c in claims if c['status'] == 'Pending'])
        total_approved_amount = sum(c['claim_amount'] for c in claims if c['status'] == 'Approved')
        
        print("\n" + "-"*100)
        print(f"Summary: Total: {total_claims} | Approved: {approved} | Rejected: {rejected} | Pending: {pending}")
        if total_approved_amount > 0:
            print(f"Total Approved Amount: ${total_approved_amount:,.2f}")
    
    def my_payment_history(self, username):
        self.clear_screen()
        print("\n ==== MY PAYMENT HISTORY ====")
        print("-"*100)
        
        payments = self.db.get_payments_by_customer(username)
        
        if not payments:
            print("No payments made yet!")
            return
        
        print(f"{'Payment ID':<12} {'Policy ID':<12} {'Amount':<12} {'Method':<20} {'Date':<20} {'Status':<10}")
        print("-"*100)
        
        for p in payments:
            print(f"{p['payment_id']:<12} {p['policy_id']:<12} ${p['amount']:<11,.2f} "
                  f"{p.get('payment_method', 'N/A'):<20} {p['payment_date']:<20} {p.get('status', 'Completed'):<10}")
        
        total_paid = sum(p['amount'] for p in payments)
        latest_payment = max(payments, key=lambda x: x['payment_date']) if payments else None
        
        print("\n" + "-"*100)
        print(f"Total Payments: {len(payments)} | Total Amount Paid: ${total_paid:,.2f}")
        if latest_payment:
            print(f"Latest Payment: {latest_payment['payment_date']} - ${latest_payment['amount']:,.2f}")
    
    def update_profile(self, customer):
        self.clear_screen()
        print("\n ==== UPDATE PROFILE ====")
        print("-"*40)
        
        print(f"Current Profile Information:")
        print(f"  Name: {customer.get('name', 'N/A')}")
        print(f"  Email: {customer.get('email', 'N/A')}")
        print(f"  Phone: {customer.get('phone', 'N/A')}")
        print(f"  Address: {customer.get('address', 'N/A')}")
        
        print("\nLeave blank to keep current values")
        
        name = input(f"\nNew Name [{customer.get('name', '')}]: ")
        email = input(f"New Email [{customer.get('email', '')}]: ")
        phone = input(f"New Phone [{customer.get('phone', '')}]: ")
        address = input(f"New Address [{customer.get('address', '')}]: ")
        
        print("\nPassword Change (Optional):")
        change_password = input("Change password? (yes/no): ")
        
        updated_data = {}
        if name: updated_data['name'] = name
        if email: updated_data['email'] = email
        if phone: updated_data['phone'] = phone
        if address: updated_data['address'] = address
        
        if change_password.lower() == 'yes':
            current_password = getpass.getpass("Current password: ")
            new_password = getpass.getpass("New password: ")
            confirm_password = getpass.getpass("Confirm new password: ")
            
            if new_password == confirm_password:
                if self.db.change_password(customer['username'], current_password, new_password):
                    updated_data['password'] = new_password
                    print("\n✓ Password updated successfully!")
                else:
                    print("\n✗ Current password is incorrect!")
            else:
                print("\n✗ Passwords do not match!")
        
        if updated_data:
            try:
                self.db.update_customer(customer['username'], updated_data)
                print("\n✓ Profile updated successfully!")
            except ValueError as e:
                print(f"\n✗ Error: {e}")
        else:
            print("\nNo changes made.")
        
        print("\nUpdated Profile:")
        updated_customer = self.db.get_customer_by_username(customer['username'])
        if updated_customer:
            print(f"  Name: {updated_customer.get('name', 'N/A')}")
            print(f"  Email: {updated_customer.get('email', 'N/A')}")
            print(f"  Phone: {updated_customer.get('phone', 'N/A')}")
            print(f"  Address: {updated_customer.get('address', 'N/A')}")
    
    def submit_query(self, username):
        self.clear_screen()
        print("\n ==== SUBMIT QUERY ====")
        print("-"*40)
        
        print("\nWhat would you like to ask?")
        print("1. Policy Information")
        print("2. Claim Status")
        print("3. Payment Issues")
        print("4. General Inquiry")
        
        try:
            query_type = int(input("\nSelect query type (1-4): "))
            message = input("\nEnter your detailed message: ")
            
            if not message:
                print("Message cannot be empty!")
                return
            
            query = Query(
                customer_username=username,
                message=f"[Type: {query_type}] {message}"
            )
            
            self.db.add_query(query.to_dict())
            
            print("\n" + "="*50)
            print("✓ QUERY SUBMITTED SUCCESSFULLY!")
            print("="*50)
            print(f"\nQuery ID: {query.query_id}")
            print(f"Status: Pending")
            print("\nOur team will review your query and respond shortly.")
            
        except ValueError:
            print("Invalid input!")
    
    def view_query_status(self, username):
        self.clear_screen()
        print("\n ==== MY QUERIES ====")
        print("-"*120)
        
        queries = self.db.get_all_queries()
        my_queries = [q for q in queries if q['customer_username'] == username]
        
        if not my_queries:
            print("You haven't submitted any queries yet!")
            return
        
        print(f"{'Query ID':<12} {'Message':<50} {'Status':<12} {'Submitted':<20} {'Response':<30}")
        print("-"*120)
        
        for q in my_queries:
            response = q.get('response', 'N/A')[:27] + "..." if len(q.get('response', '')) > 30 else q.get('response', 'N/A')
            message = q['message'][:47] + "..." if len(q['message']) > 50 else q['message']
            print(f"{q['query_id']:<12} {message:<50} "
                  f"{q['status']:<12} {q['date_submitted'][:19]:<20} {response:<30}")

# ============================================
# MAIN SYSTEM CLASS
# ============================================
class InsuranceManagementSystem:
    def __init__(self):
        self.db = Database()
        self.admin_panel = AdminPanel(self.db)
        self.customer_panel = CustomerPanel(self.db)
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        print("""
╔══════════════════════════════════════════════════════╗
║          INSURANCE MANAGEMENT SYSTEM                 ║
║         Secure . Reliable . Trustworthy              ║
║            SQL Database Powered                      ║
╚══════════════════════════════════════════════════════╝
        """)
    
    def login_page(self):
        while True:
            self.clear_screen()
            self.print_banner()
            print("\nSELECT LOGIN TYPE:")
            print("1. Admin Login")
            print("2. Customer Login")
            print("3. Exit")
            
            choice = input("\nEnter your choice (1-3): ")
            
            if choice == '1':
                self.admin_login()
            elif choice == '2':
                self.customer_login()
            elif choice == '3':
                self.clear_screen()
                print("\nThank you for using Insurance Management System!")
                print("Goodbye!\n")
                self.db.close()
                break
            else:
                print(" Invalid choice!")
                input("Press Enter to continue...")
    
    def admin_login(self):
        self.clear_screen()
        print("\n ADMIN LOGIN")
        print("-"*30)
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        
        admin = self.db.verify_admin(username, password)
        if admin:
            print(f"\n Welcome, {admin['name']}!")
            self.db.log_action(username, 'admin', 'Login', 'Admin logged in')
            input("Press Enter to continue...")
            self.admin_panel.admin_menu(admin)
        else:
            print("\n Invalid credentials!")
            input("Press Enter to continue...")
    
    def customer_login(self):
        self.clear_screen()
        print("\n CUSTOMER LOGIN")
        print("-"*30)
        print("1. Login")
        print("2. Register (Contact Admin)")
        choice = input("\nSelect option: ")
        
        if choice == '1':
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            customer = self.db.verify_customer(username, password)
            if customer:
                print(f"\n Welcome, {customer['name']}!")
                self.db.log_action(username, 'customer', 'Login', 'Customer logged in')
                input("Press Enter to continue...")
                self.customer_panel.customer_menu(customer)
            else:
                print("\n Invalid credentials!")
                input("Press Enter to continue...")
        else:
            print("\n Please contact admin to register!")
            input("Press Enter to continue...")

# ============================================
# MAIN ENTRY POINT
# ============================================
def main():
    try:
        app = InsuranceManagementSystem()
        app.login_page()
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
    finally:
        # Ensure database connection is closed
        if 'app' in locals():
            app.db.close()

if __name__ == "__main__":
    main()