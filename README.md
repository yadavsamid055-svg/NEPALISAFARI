# NepaliSafari local application

## Start the application

1. Install Python 3.11 or later.
2. From this folder, install the required packages:

   ```powershell
   python -m pip install -r requirements.txt
   ```

3. Create the first administrator account:

   ```powershell
   python server.py create-admin
   ```

   Use a unique password with at least 12 characters. The command prompts for it without displaying the password.

4. Start the local server:

   ```powershell
   python server.py
   ```

5. Open <http://127.0.0.1:8000>.

The SQLite database and generated session/document-encryption keys are created under `.instance`. Back up that directory securely; losing the encryption key makes stored identity images unreadable. Do not commit or share `.instance`.

## Current integrations

Email/phone-and-password accounts, persistent rides and bookings, encrypted profile/licence images, owner review, chat, complaints, ratings, and referral tracking run on the local server. Password recovery and phone-number verification are not configured.

Online eSewa and Khalti payments are not available yet. The site will not mark a booking paid or claim money was transferred until a payment gateway integration and merchant credentials are implemented. Referral points are recorded but cannot be redeemed.

This is a local installation, not a public production deployment. Do not expose Flask's local server to the internet. Public launch requires production hosting, HTTPS, operational monitoring and backups, account recovery, privacy/retention controls, and completed payment and identity-review procedures.
