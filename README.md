# HelloHelp - Client Support Ticket System

A comprehensive client support ticket system built with Python and Flask that allows for efficient ticket management, team collaboration, and customer support.

## Features

### Admin Features
- Dashboard with ticket statistics and charts
- Manage staff members and teams
- Set SLAs and categories
- Add FAQs and predefined chatbot responses
- View and manage all tickets
- Assign tickets to team members

### Manager Features
- View and manage team tickets
- Assign tickets to team members
- Monitor team performance
- Track SLA compliance

### Team Member Features
- View assigned tickets
- Update ticket status
- Respond to tickets
- Track personal performance metrics

### Client Features
- Raise support tickets
- View ticket status
- Access FAQs
- Chat with support bot
- Track ticket history

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/hellohelp.git
cd hellohelp
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file with the following variables:
```
SECRET_KEY=your-secret-key
MAIL_PASSWORD=your-email-password
```

5. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

6. Run the application:
```bash
python app.py
```

## Usage

1. Access the application at `http://localhost:5000`
2. Login with the default admin credentials:
   - Email: ashokshivani875@gmail.com
   - Password: Shivani@123

## Project Structure

```
hellohelp/
├── app.py              # Main application file
├── requirements.txt    # Project dependencies
├── templates/          # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── admin_dashboard.html
│   ├── manager_dashboard.html
│   ├── team_member_dashboard.html
│   ├── client_dashboard.html
│   └── ticket_details.html
└── static/            # Static files (CSS, JS, images)
```

## Database Models

- User: Stores user information (admin, manager, team member, client)
- Team: Manages team information and members
- Ticket: Stores ticket details and status
- Reply: Stores ticket replies
- FAQ: Stores frequently asked questions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 