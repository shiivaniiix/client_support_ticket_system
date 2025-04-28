from app import app, db, User, FAQ, Team, Ticket, Reply, Attachment
from datetime import datetime

def init_db():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        
        # Create all tables
        db.create_all()
        
        # Create admin user
        admin = User(
            email='ashokshivani875@gmail.com',
            first_name='Admin',
            last_name='User',
            role='admin',
            created_at=datetime.utcnow()
        )
        admin.set_password('Shivani@123')
        db.session.add(admin)
        
        # Create sample FAQs
        sample_faqs = [
            FAQ(question='How do I create a new ticket?', 
                answer='Click on Create Ticket in the navigation menu and fill out the form.',
                category='General'),
            FAQ(question='What is the response time for tickets?',
                answer='Response times vary by priority: Urgent (2 hours), High (4 hours), Medium (8 hours), Low (24 hours).',
                category='Technical'),
            FAQ(question='How do I reset my password?',
                answer='Click on Forgot Password on the login page and follow the instructions.',
                category='Account'),
            FAQ(question='What payment methods do you accept?',
                answer='We accept all major credit cards, PayPal, and bank transfers.',
                category='Billing')
        ]
        
        for faq in sample_faqs:
            db.session.add(faq)
        
        db.session.commit()
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_db() 