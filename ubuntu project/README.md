# Ubuntu Waterhub Africa

## Run the application

This version requires Node.js 22.13.0 or newer. Start it from PowerShell:

```powershell
npm start
```

On first launch, the server prints a one-time PIN setup code in its console. Open `http://localhost:3000` in a browser and use the separate **Create Admin and Student PINs** section to enter that code and create separate PINs. PINs can contain any characters, including letters, numbers, spaces, and symbols, up to 128 characters, and cannot be identical. To sign in later, use the **Log in with PIN** section: choose Student or Admin, enter its PIN, then press Enter. PINs are stored as salted hashes in the SQLite database at `data\waterhub.sqlite`; the database is excluded from source control. If an existing installation has not set PINs yet, restart the server and use its newly printed setup code to configure both.

Choose **Student** or **Admin** on the sign-in screen and enter the corresponding PIN. The Student account can register students and check them in. Admin can also view and remove students, manage events, view or clear notification logs, and change either PIN from the Accounts tab. PIN changes require the current Admin PIN; changing the Admin PIN signs out all Admin sessions. If a PIN is forgotten, use **Forgot a PIN?** and enter the one-time recovery code printed in the server console when it started. Recovery changes one account PIN, signs that account out on all devices, and consumes the code; restart the server to generate a fresh code. Keep setup and recovery codes private. Login attempts are rate limited.

## Guardian SMS notifications

Registration and check-in SMS are sent through Africa's Talking to the guardian phone number entered on the registration form (spaces and hyphens are removed before sending). Create an account and obtain an API key, then configure the server environment before starting it. In PowerShell:

```powershell
$env:AT_USERNAME = "your-africas-talking-username"
$env:AT_API_KEY = "your-api-key"
# Optional: set this only if you have an approved sender ID.
$env:AT_SENDER_ID = "your-approved-sender-id"
# Optional: use the Africa's Talking sandbox while testing.
$env:AT_ENVIRONMENT = "sandbox"
npm start
```

Omit `AT_ENVIRONMENT` (or set it to another value) for live sending. Keep API credentials private and out of source control. Guardians must consent on the registration form before the server sends registration and check-in messages. Older student records have no recorded consent and are not sent check-in SMS until consent is collected. The notification log records whether the provider accepted, rejected, or was not configured for each message; provider acceptance is not a handset delivery receipt. Without both `AT_USERNAME` and `AT_API_KEY`, SMS is not sent.

If PIN sign-in reports that the server cannot be reached, start the app from the project folder with `npm start`, then open `http://localhost:3000` and reload. Do not open `index.html` as a local file; PIN authentication requires the server.

For deployment, use HTTPS and set `NODE_ENV=production` so the session cookie is marked Secure. Keep the `data` folder private and back it up securely. The existing browser-only app's localStorage records are separate from the server database and are not migrated automatically.
