# LaunchLens

LaunchLens scans a public web app URL for observable launch-readiness signals and turns the findings into an AI coding prompt.

## MVP

- Next.js App Router
- Tailwind CSS
- No login
- No database
- Public URL scanning
- HTTPS and HTTP status checks
- Common security-header checks
- HTML title, viewport and description checks
- Basic public-token pattern detection
- Groq-powered summary and fix prompt
- Copy-to-clipboard UI

## Environment

Copy `.env.example` to `.env.local` and add:

```
GROQ_API_KEY=...
```

LaunchLens uses Groq's `openai/gpt-oss-120b` model for the optional AI explanation.

## Run

```bash
npm install
npm run dev
```

Then open http://localhost:3000.

## Important scope

A public URL scanner cannot prove that an application is secure. It only reports signals visible from the public response. It does not inspect private source code, authenticated routes, internal services, databases, or deployment configuration.

The scanner also blocks obvious private/local URL targets and validates redirect destinations to reduce SSRF risk.
