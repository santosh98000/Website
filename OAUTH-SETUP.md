# WHITE DEVIL OAuth setup

The HTML cannot read a Google/Apple/GitHub account from the browser. The secure flow is:
provider -> OAuth callback on this server -> verified profile -> local session.

## Google
Create an OAuth 2.0 Web Client. Add:
`https://YOUR-DOMAIN/auth/google/callback`
Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.

## GitHub
Create an OAuth App and set Authorization callback URL to:
`https://YOUR-DOMAIN/auth/github/callback`
Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET.

## Apple
For web Sign in with Apple, create/configure a Services ID, associate your website/domain, and create a Sign in with Apple private key. Set APPLE_CLIENT_ID, APPLE_TEAM_ID, APPLE_KEY_ID and APPLE_PRIVATE_KEY.

## Run
1. Copy .env.example to .env and fill provider credentials.
2. Install Node.js dependencies: `npm install`
3. Start: `npm start`
4. Open the site through the server, not by double-clicking the HTML file.

Do not put client secrets or Apple private keys in index.html.
