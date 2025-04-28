from app import app, db, User, FAQ
from datetime import datetime

def setup_database():
    with app.app_context():
        # Create admin user
        admin = User.query.filter_by(email='ashokshivani875@gmail.com').first()
        if not admin:
            admin = User(
                email='ashokshivani875@gmail.com',
                first_name='Admin',
                last_name='User',
                role='admin',
                created_at=datetime.utcnow()
            )
            admin.set_password('Shivani@123')
            db.session.add(admin)
            print("Admin user created successfully!")
        
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
            if not FAQ.query.filter_by(question=faq.question).first():
                db.session.add(faq)
        
        db.session.commit()
        print("Sample FAQs added successfully!")

if __name__ == '__main__':
    setup_database() 