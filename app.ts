import { opine, serveStatic, HTTPOptions } from "https://deno.land/x/opine@2.2.0/mod.ts"; 

const app = opine();

app.use(serveStatic("./src"));

// "Development" HTTPS
const appConfig: HTTPOptions = {
	port: 3000
};

// Start development server
app.listen(appConfig,
	() => console.log("server has started on http://localhost:3000 🚀"),
);