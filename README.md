# webauthn-debugger

This is a serverless webauthn debugger, which works by running the RP (backend) in the browser. You can copy the content of /src to any web server, and try out webauthn.

Uses [fido2-lib](https://www.npmjs.com/package/fido2-lib) as RP "backend".

The repository also includes a Deno development server, use by

1. Install Deno
2. Checkout and enter this repo
3. `deno task start`
4. Browse to `http://localhost:3000`

Based on [main](https://github.com/Hexagon/webauthn-skeleton)