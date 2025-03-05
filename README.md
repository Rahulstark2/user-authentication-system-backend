# User Authentication System Backend

This is the backend for the User Authentication System, which handles user registration, login, and other authentication related endpoints using Express, Node.js, MongoDB, JWT.

## Getting Started

Follow the steps below to set up and run the project on your local machine:

### Prerequisites
- Node.js and npm installed on your system.
- MongoDB Atlas or a compatible MongoDB instance.

### Installation

1. **Clone the Repository**  
   Clone the repository to your local machine using the following command: `git clone <repository-url>`

2. **Navigate to the Project Directory**  
   Change into the project directory: `cd user-authentication-system-backend`

3. **Install Dependencies**  
   Install the required dependencies using npm: `npm install`

4. **Create a `.env` File**  
   In the root folder of the project, create a `.env` file and add the following variables:

    - **JWT_SECRET**: A secret key used to sign and verify JSON Web Tokens (JWT).
    - **MONGODB_URI**: The connection string to your MongoDB database.
    - **EMAIL**: The email address used for sending authentication-related emails (e.g., verification or password reset).
    - **EMAIL_PASS**: The application-specific password for the email account.

5. **Start the Server**  
Run the server using the following command: `npm start`

The server will start on the specified port (default: `3000`). You can access it at `http://localhost:3000`.

## Features
- User registration and login.
- Change name, password and delete account by user.
- Password hashing and validation.
- JWT-based authentication.
- Email notifications for verification and password resets.
- Deletion of profile and fetching all profile by admin
  
