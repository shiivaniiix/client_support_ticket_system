from app import db, User, app
from werkzeug.security import generate_password_hash, check_password_hash

# Store known passwords for development
KNOWN_PASSWORDS = {
    'ashokshivani875@gmail.com': 'Shivani@123',
    'manager@example.com': 'manager123',
    'staff@example.com': 'staff123',
    'client@example.com': 'client123',
    'shivani875@gmail.com': 'Shivani@123'  # Adding staff member's credentials
}

def list_all_users():
    """List all users with their credentials"""
    users = User.query.all()
    print("\n=== All Users ===")
    for user in users:
        print(f"\nEmail: {user.email}")
        print(f"Name: {user.first_name} {user.last_name}")
        print(f"Role: {user.role}")
        print(f"Phone: {user.phone}")
        if user.team:
            print(f"Team: {user.team.name}")
        # Show actual password if known
        if user.email in KNOWN_PASSWORDS:
            print(f"Password: {KNOWN_PASSWORDS[user.email]}")
        else:
            print("Password: [Not tracked]")
        print("-" * 50)

def reset_user_password(email, new_password):
    """Reset a user's password"""
    user = User.query.filter_by(email=email).first()
    if user:
        user.set_password(new_password)
        db.session.commit()
        # Update known passwords
        KNOWN_PASSWORDS[email] = new_password
        print(f"\nPassword reset successful for {email}")
        print(f"New password: {new_password}")
    else:
        print(f"\nUser with email {email} not found!")

def create_test_users():
    """Create some test users with known passwords"""
    test_users = [
        {
            'email': 'manager@example.com',
            'first_name': 'Test',
            'last_name': 'Manager',
            'role': 'manager',
            'password': 'manager123',
            'phone': '1234567890'
        },
        {
            'email': 'staff@example.com',
            'first_name': 'Test',
            'last_name': 'Staff',
            'role': 'team_member',
            'password': 'staff123',
            'phone': '1234567890'
        },
        {
            'email': 'client@example.com',
            'first_name': 'Test',
            'last_name': 'Client',
            'role': 'client',
            'password': 'client123',
            'phone': '1234567890'
        }
    ]
    
    for user_data in test_users:
        # Check if user already exists
        existing_user = User.query.filter_by(email=user_data['email']).first()
        if not existing_user:
            user = User(
                email=user_data['email'],
                first_name=user_data['first_name'],
                last_name=user_data['last_name'],
                role=user_data['role'],
                phone=user_data['phone']
            )
            user.set_password(user_data['password'])
            db.session.add(user)
            print(f"Created user: {user_data['email']}")
            print(f"Password: {user_data['password']}")
        else:
            print(f"User already exists: {user_data['email']}")
            print(f"Password: {user_data['password']}")
    
    db.session.commit()
    print("\nTest users created successfully!")

def show_all_credentials():
    """Show all known credentials"""
    print("\n=== Known User Credentials ===")
    for email, password in KNOWN_PASSWORDS.items():
        user = User.query.filter_by(email=email).first()
        if user:
            print(f"\nEmail: {email}")
            print(f"Password: {password}")
            print(f"Role: {user.role}")
            print("-" * 30)

def main():
    with app.app_context():
        print("User Credentials Management Tool")
        print("1. List all users")
        print("2. Reset user password")
        print("3. Create test users")
        print("4. Show all known credentials")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == '1':
            list_all_users()
        elif choice == '2':
            email = input("Enter user email: ")
            new_password = input("Enter new password: ")
            reset_user_password(email, new_password)
        elif choice == '3':
            create_test_users()
        elif choice == '4':
            show_all_credentials()
        elif choice == '5':
            print("Goodbye!")
        else:
            print("Invalid choice!")

if __name__ == '__main__':
    main() 