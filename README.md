# webauthn-debugger

This is a serverless webauthn debugger, which works by running the RP (backend) in the browser. You can copy the content of /src to any web server, and try out webauthn.

Uses [fido2-lib](https://www.npmjs.com/package/fido2-lib) as RP.

Live at [56k.guru/webauthn-debugger](https://56k.guru/webauthn-debugger)

The repository also includes a Deno development server, use by

1. Install Deno
2. Checkout and enter this repo
3. `deno task start`
4. Browse to `http://localhost:3000`
5. Adjust at least `origin` in options to match the base of your URL.

Based on [github.com/Hexagon/webauthn-skeleton](https://github.com/Hexagon/webauthn-skeleton)