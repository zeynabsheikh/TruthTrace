#!/usr/bin/env python
"""
Database Initialization Script
Run this once before starting the application
"""

from app import app, db

def init_database():
    """Create all database tables"""
    with app.app_context():
        print("🔄 Creating database tables...")
        db.drop_all()  # Remove existing tables (comment this line if you want to keep data)
        db.create_all()
        print(" Database tables created successfully!")
        print(" Database location: instance/database.db")
        
        # Verify tables
        from app import User, Analysis
        print("\nCreated tables:")
        print(f"   - User table")
        print(f"   - Analysis table")
        print("\n You can now run: python app.py")

if __name__ == '__main__':
    init_database()