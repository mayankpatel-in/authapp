
API Documentation

\=================

1. User Registration

\--------------------

- Endpoint: /api/register/
- Method: POST
- Authentication: No authentication required
- Purpose: This endpoint is used for registering new users.
- Data Params:
- email [string] : User's email
- password [string] : User's password (min 8 characters)
- role [string] (optional) : User's role (default is "solution seeker")

- Success Response:
- Code: 201 CREATED
- Content: { message : "User created successfully" }

- Error Response:
- Code: 400 BAD REQUEST
- Content: { error : "Email and password are required" }

or

- Content: { error : "User with this email already exists" }

2\. User Login

\-------------

- Endpoint: /api/login/
- Method: POST
- Authentication: No authentication required
- Purpose: This endpoint is used for user login. Returns JWT token.
- Data Params:
- email [string] : User's email
- password [string] : User's password

- Success Response:
- Code: 200 OK
- Content:

{

"access": "access\_token\_here",

"refresh": "refresh\_token\_here"

}

- Error Response:
- Code: 400 BAD REQUEST
- Content: { error : "Email and password are required" }

or

- Code: 401 UNAUTHORIZED
- Content: { error : "Invalid email or password" }

3\. Send OTP

\-----------

- Endpoint: /api/send\_otp/
- Method: POST
- Authentication: No authentication required
- Purpose: Send OTP to the user's email.
- Data Params:
- email [string] : User's email

- Success Response:
- Code: 200 OK
- Content: { message : "OTP has been sent to your email." }

- Error Response:
- Code: 400 BAD REQUEST
- Content: { error : "Email is required" }

or

- Content: { error : "User with this email does not exist." }

4\. Verify OTP

\-------------

- Endpoint: /api/verify\_otp/
- Method: POST
- Authentication: No authentication required
- Purpose: Verify the received OTP from the user.
- Data Params:
- email [string] : User's email
- otp [string] : OTP received by the user

- Success Response:
- Code: 200 OK
- Content:

{

"access": "access\_token\_here",

"refresh": "refresh\_token\_here"

}

- Error Response:
- Code: 400 BAD REQUEST
- Content: { error : "Both email and OTP are required." }

or

- Content: { error : "Invalid or expired OTP." }

or

- Content: { error : "OTP not sent for this user." }

[... other endpoints ...]

5\. Change Password

\------------------

- Endpoint: /api/change\_password/
- Method: PUT
- Authentication: Required - JWT Token
- Purpose: Allows a user to change their password.
- Data Params:
- old\_password [string]: User's current password
- new\_password [string]: User's new password
- confirm\_new\_password [string]: Confirmation of the new password

- Success Response:
- Code: 200 OK
- Content: { message : "Password updated successfully" }

- Error Response:
- Code: 400 BAD REQUEST
- Content: { error : "Old password is not correct" }

or

- Content: { error : "New password is required" }

or

- Content: { error : "Passwords do not match" }

6\. Forgot Password

\------------------

- Endpoint: /api/forgot\_password/
- Method: POST
- Authentication: No authentication required
- Purpose: Sends a password reset link to the user's email.
- Data Params:
- email [string]: User's registered email address

- Success Response:
- Code: 200 OK
- Content: { message : "We have sent you an email to reset your password" }

- Error Response:
- Code: 404 NOT FOUND
- Content: { error : "There is no user with this email address" }

7\. Password Reset Confirm

\-------------------------

- Endpoint: /api/password\_reset\_confirm/
- Method: POST
- Authentication: No authentication required
- Purpose: Allows a user to reset their password using a valid token.
- URL Params:
- uidb64 [string]: The user's ID in base 64
- token [string]: The password reset token
- Data Params:
- new\_password [string]: User's new password

- Success Response:
- Code: 200 OK
- Content: { message : "Password reset successfully." }

- Error Response:
- Code: 400 BAD REQUEST
- Content: { error : "Invalid token or user ID" }

or

- Content: { error : "Password cannot be empty." }

8\. Create User Profile

\----------------------

- Endpoint: /api/create\_profile/
- Method: POST
- Authentication: Required - JWT Token
- Purpose: Creates a profile for the current user.
- Data Params:
- first\_name [string]: User's first name
- last\_name [string]: User's last name
- phone\_number [string]: User's phone number

- Success Response:
- Code: 201 CREATED
- Content: { message : "Profile created successfully" }

- Error Response:
- Code: 400 BAD REQUEST
- Content: { error : "Profile already exists" }

9\. Update User Profile

\----------------------

- Endpoint: /api/update\_profile/
- Method: PUT
- Authentication: Required - JWT Token
- Purpose: Updates the profile for the current user.
- Data Params:
- first\_name [string] (optional): User's first name
- last\_name [string] (optional): User's last name
- phone\_number [string] (optional): User's phone number

- Success Response:
- Code: 200 OK
- Content: { message : "Profile updated successfully" }

- Error Response:
- Code: 404 NOT FOUND
- Content: { error : "Profile does not exist" }

10\. Solution Provider View

\--------------------------

- Endpoint: /api/solution\_provider/
- Method: GET
- Authentication: Required - JWT Token and Solution Provider role
- Purpose: Accessible for users with the Solution Provider role.
- Success Response:
- Code: 200 OK
- Content: { message : "Access granted for Solution Provider" }

11\. Solution Seeker View

\------------------------

- Endpoint: /api/solution\_seeker/
- Method: GET
- Authentication: Required - JWT Token and Solution Seeker role
- Purpose: Accessible for users with the Solution Seeker role.
- Success Response:
- Code: 200 OK
- Content: { message : "Access granted for Solution Seeker" }
