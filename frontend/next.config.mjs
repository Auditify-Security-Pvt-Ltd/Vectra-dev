/** @type {import('next').NextConfig} */

// Origin of the FastAPI backend as seen from the Next.js server process (not
// from the browser). Server-side only, so it is never embedded in client
// bundles and no tunnel URL is hard-coded in source.
const BACKEND_ORIGIN = process.env.BACKEND_ORIGIN ?? 'http://localhost:8000'

const nextConfig = {
  // Emit a self-contained server bundle (.next/standalone) so the production
  // Docker image can run `node server.js` without the full node_modules tree.
  output: 'standalone',
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  // Proxy API traffic through the Next server so the browser only ever talks to
  // the origin it loaded the app from. Without this, the client calls
  // http://localhost:8000 directly, which only resolves when the browser runs
  // on the same host as the backend — it breaks behind a tunnel or on any
  // remote device, and is blocked as mixed content on an HTTPS origin.
  async rewrites() {
    return [
      {
        source: '/api/backend/:path*',
        destination: `${BACKEND_ORIGIN}/:path*`,
      },
    ]
  },
}

export default nextConfig
