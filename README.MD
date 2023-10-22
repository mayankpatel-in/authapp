# AuthApp

AuthApp is a Django-based application designed to provide a Role based access control to user for use perticular app section. The User register, login, changepassword, forgot password, and also profile create and update features added!

## Prerequisites

Before you begin, ensure you have met the following requirements:

- You have installed the latest version of Python and Django.
- You are familiar with Python, Django, and the basics of database systems.

## Setting Up AuthApp

To set up the AuthApp project, follow these steps:

1. Clone the repository:
git clone https://github.com/mayankpatel-in/authapp.git


2. Change into the project directory:
cd authapp


3. Install the project's dependencies:
pip install -r requirements.txt


4. Set up your environment variables. Copy the sample environment file and configure it according to your needs:
cp .env.sample .env

Edit the `.env` file and update the variables (like `SECRET_KEY`, `DEBUG`, and email settings) with your own values.

5. Run the initial database migrations:
python manage.py migrate


6. Start the development server:
python manage.py runserver

Now, you can access the application at `localhost:8000` in your web browser.

## Using AuthApp

To use AuthApp API, follow these steps:

1. Register a new user by going to `localhost:8000/register`.
2. Log in with the new user credentials at `localhost:8000/login`.
3. For create new user profile `localhost:8000/profile/create/`.
4. For update user profile `localhost:8000/profile/update/`.
5. You can change user password by `localhost:8000/change_password/`.
6. Forget User password via email `localhost:8000/forgot_password/`.

let's check role based access area:

7. Only solution provider access this `localhost:8000/api/solution-provider/`.
8. Only solution seeker access this `localhost:8000/api/solution-seeker/`.

## Contact

If you want to contact me, you can reach me at `patelmayank.oc@gmail.com`.
