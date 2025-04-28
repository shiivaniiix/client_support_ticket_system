from app import app, db, User

with app.app_context():
    # Check if admin already exists
    admin = User.query.filter_by(email='ashokshivani875@gmail.com').first()
    if not admin:
        admin = User(
            email='ashokshivani875@gmail.com',
            first_name='Admin',
            last_name='User',
            role='admin'
        )
        admin.set_password('Shivani@123')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created successfully!")
    else:
        print("Admin user already exists!") 